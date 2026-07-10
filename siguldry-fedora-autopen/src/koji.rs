// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! Utilities to work with Koji for RPM signing.

use std::{
    collections::HashMap,
    ffi::CStr,
    path::PathBuf,
    thread::{self, JoinHandle},
};

use anyhow::Context;
use pyo3::{
    Bound, FromPyObject, Py, Python,
    types::{PyAny, PyAnyMethods, PyIterator, PyModule},
};
use tokio::sync::{mpsc, oneshot};
use tracing::instrument;

use crate::config::Koji;

const KOJI: &CStr = pyo3::ffi::c_str!(include_str!("koji_utils.py"));

/// Operations performed against Koji.
///
/// This trait abstracts away the Python actor so testing is easier.
pub trait KojiOps: Clone + Send + Sync + 'static {
    /// Retrieve the details for all the RPMs within a build.
    fn build_info(
        &self,
        build_id: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<Build>> + Send;

    /// Retrieve the next chunk of RPMs in a tag that have not been signed by the provided key.
    fn rpms_to_sign_in_tag(
        &self,
        tag_name: &str,
        sigkey: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<RpmChunk>>> + Send;

    /// Add a signature header to the RPM in Koji.
    fn add_signature(
        &self,
        rpm_id: i64,
        expected_sigkey: String,
        signed_package: PathBuf,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;

    /// Move the build from one tag to another.
    ///
    /// Returns the task ID of the move operation.
    fn move_build(
        &self,
        build_id: i64,
        expected_sigkey: String,
        tag_from: String,
        tag_to: String,
    ) -> impl std::future::Future<Output = anyhow::Result<i64>> + Send;

    /// Request Koji write out a signed copy of the RPM.
    fn write_signed_rpm(
        &self,
        rpm_id: i64,
        sigkey: String,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

/// An RPM that is part of a build.
#[derive(Debug, Clone, Default, FromPyObject)]
pub struct Rpm {
    pub id: i64,
    pub draft: bool,
    pub epoch: Option<i64>,
    pub name: String,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub size: u64,
    pub url: String,
    pub sha256sum: String,
    pub existing_sigkeys: Vec<String>,
}

impl Rpm {
    pub fn filename(&self) -> String {
        format!(
            "{}:{}-{}-{}.{}.rpm",
            self.epoch.unwrap_or(0),
            self.name,
            self.version,
            self.release,
            self.arch
        )
    }
}

#[derive(Debug, Clone, Default, FromPyObject)]
pub struct TagEvent {
    pub create_event: i64,
    pub creator_name: String,
    pub tag_name: String,
}

/// A build in Koji.
///
/// A single build can have many RPMs, and we have to sign all of them before moving the build
/// from one tag to another.
#[derive(Debug, Clone, Default, FromPyObject)]
pub struct Build {
    pub id: i64,
    pub tag_history: Vec<TagEvent>,
    pub rpms: Vec<Rpm>,
}

impl Build {
    pub(crate) fn active_tag(&self) -> Option<TagEvent> {
        self.tag_history
            .iter()
            .max_by_key(|e| e.create_event)
            .cloned()
    }
}

#[derive(Debug)]
enum KojiRequest {
    BuildInfo {
        build_id: i64,
    },
    /// Request a list of RPMs in a tag that have not been signed by the provided key.
    UnsignedChunk {
        /// The tag to query for unsigned RPMs.
        tag: String,
        /// Filter out any RPMs that have a signature from this key.
        sigkey: String,
    },
    AddSignature {
        rpm_id: i64,
        expected_sigkey: String,
        signed_package: PathBuf,
    },
    WriteSignedRpm {
        rpm_id: i64,
        sigkey: String,
    },
    MoveBuild {
        build_id: i64,
        expected_sigkey: String,
        tag_from: String,
        tag_to: String,
    },
}

#[derive(Debug)]
enum KojiResponse {
    BuildInfo(anyhow::Result<Build>),
    UnsignedChunk(anyhow::Result<Option<RpmChunk>>),
    AddSignature(anyhow::Result<()>),
    WriteSignedRpm(anyhow::Result<()>),
    /// Returns the task ID of the move task
    MoveBuild(anyhow::Result<i64>),
}

#[derive(Debug, Clone, Default, FromPyObject)]
pub struct RpmChunk {
    /// The name of the tag this re-signing operation belongs to
    pub tag_name: String,
    /// The sigkey being used for this re-signing operation
    pub sigkey: String,
    /// Total number of builds in the tag
    pub total_builds: u64,
    /// Number of builds per chunk
    pub builds_in_chunk: u64,
    /// Number of build chunks that have been fully processed.
    pub build_chunks_processed: u64,
    /// Number of RPMs in the current build chunk
    pub rpms_in_build_chunk: u64,
    /// Running total number of RPMs examined
    pub rpms_processed: u64,
    /// Running total of RPMs that have needed signing
    pub rpms_missing_signature: u64,
    /// List of RPMs that need to be signed in this chunk.
    ///
    /// This list may be empty, which simply means the current chunk
    /// was all signed. We still yield this to allow metrics to be
    /// reported and to have a reliable number of Koji queries between
    /// yielding.
    pub rpms_to_sign: Vec<Rpm>,
}

/// Tracks an iterator from the `rpms_to_sign_in_tag()` Python method
/// in the koji_utils.py module.
#[derive(Debug)]
struct TagsToSign {
    tags_to_sign: HashMap<(String, String), Py<PyIterator>>,
    chunk_size: u32,
}

impl TagsToSign {
    fn new(chunk_size: u32) -> Self {
        Self {
            tags_to_sign: HashMap::new(),
            chunk_size,
        }
    }

    fn next<'py>(
        &mut self,
        py: Python<'py>,
        bound_client: &Bound<'py, PyAny>,
        tag: String,
        sigkey: String,
    ) -> anyhow::Result<Option<RpmChunk>> {
        let tag_and_sigkey = (tag.clone(), sigkey);
        if !self.tags_to_sign.contains_key(&tag_and_sigkey) {
            let generator = bound_client
                .call_method1(
                    "rpms_to_sign_in_tag",
                    (&tag_and_sigkey.0, &tag_and_sigkey.1, self.chunk_size),
                )
                .context("Failed to call rpms_to_sign_in_tag")?;
            let generator = PyIterator::from_object(&generator)
                .context("Failed to convert rpms_to_sign_in_tag return to iterator")?
                .unbind();
            self.tags_to_sign.insert(tag_and_sigkey.clone(), generator);
        }
        let mut generator = self
            .tags_to_sign
            .get(&tag_and_sigkey)
            .expect("The generator was just inserted")
            .bind(py)
            .to_owned();

        let chunk = match generator.next() {
            Some(Ok(chunk)) => {
                let chunk = chunk
                    .extract::<RpmChunk>()
                    .context("Programmer error: failed to extract Koji RPM chunk")?;
                crate::metrics_utils::rpms_resign_missing_signature(tag.clone())
                    .set(chunk.rpms_missing_signature as f64);
                crate::metrics_utils::rpms_resign_queried(tag.clone())
                    .set(chunk.rpms_processed as f64);

                tracing::info!(
                    chunk.tag_name,
                    chunk.sigkey,
                    chunk.total_builds,
                    chunk.builds_in_chunk,
                    chunk.build_chunks_processed,
                    chunk.rpms_in_build_chunk,
                    "New chunk of RPMs from Koji successfully queried"
                );

                Some(chunk)
            }
            Some(Err(error)) => {
                // If the iterator crashed, we don't want to resume it next go around, so
                // drop it and start over. This might cause problems if it crashes very near
                // the end and Koji returns the list of builds in a deterministic way.
                drop(generator);
                self.tags_to_sign.remove(&tag_and_sigkey);
                tracing::error!(
                    ?error,
                    tag = &tag_and_sigkey.0,
                    sigkey = &tag_and_sigkey.1,
                    "Error while iterating tag to sign; restarting tag enumeration..."
                );
                return Err(error.into());
            }
            None => {
                self.tags_to_sign.remove(&tag_and_sigkey);
                None
            }
        };

        Ok(chunk)
    }
}

#[derive(Debug)]
pub struct KojiActor {
    python_thread: JoinHandle<Result<(), anyhow::Error>>,
    request_tx: mpsc::Sender<(KojiRequest, oneshot::Sender<KojiResponse>)>,
    readonly: bool,
}

impl KojiActor {
    pub fn new(config: Koji) -> anyhow::Result<Self> {
        let (request_tx, mut rx) = mpsc::channel::<(KojiRequest, oneshot::Sender<KojiResponse>)>(2);
        let client = Python::attach(|py| {
            let module = PyModule::from_code(py, KOJI, c"koji_utils.py", c"")?;
            match &config.auth {
                crate::config::KojiAuthentication::Kerberos {
                    principal,
                    keytab,
                    ccache,
                } => module
                    .getattr("Client")?
                    .call(
                        (
                            &config.url,
                            principal,
                            keytab.as_ref(),
                            ccache.as_ref(),
                            config.readonly,
                        ),
                        None,
                    )
                    .context("Failed to create Koji client")
                    .map(|obj| obj.unbind()),
            }
        })?;

        if config.readonly {
            tracing::info!(
                config.readonly,
                "All Koji operations will be read-only and no authentication will be attempted"
            );
        }

        let python_thread = thread::Builder::new()
            .spawn(move || {
                let mut tags_to_sign = TagsToSign::new(1000);

                while let Some((request, respond_to)) = rx.blocking_recv() {
                    let response = Python::attach(|py| {
                        // Be careful to not break out of this receive loop on errors.
                        let bound_client = client.bind(py);
                        match request {
                            KojiRequest::BuildInfo { build_id } => {
                                let result = bound_client
                                    .call_method1("build_info", (build_id,))
                                    .context("Koji build_info call failed")
                                    .and_then(|obj| {
                                        obj.extract::<Build>()
                                            .context("Failed to extract Koji Build")
                                    });
                                KojiResponse::BuildInfo(result)
                            }
                            KojiRequest::UnsignedChunk { tag, sigkey } => {
                                let result = tags_to_sign.next(py, bound_client, tag, sigkey);
                                KojiResponse::UnsignedChunk(result)
                            }
                            KojiRequest::AddSignature {
                                rpm_id,
                                expected_sigkey,
                                signed_package,
                            } => {
                                let result = bound_client
                                    .call_method1(
                                        "add_signature",
                                        (rpm_id, expected_sigkey, signed_package),
                                    )
                                    .context("Koji add_signature call failed")
                                    .map(|_| ());
                                KojiResponse::AddSignature(result)
                            }
                            KojiRequest::WriteSignedRpm { rpm_id, sigkey } => {
                                let result = bound_client
                                    .call_method1("write_signed_rpm", (rpm_id, sigkey))
                                    .context("Koji write_signed_rpm call failed")
                                    .map(|_| ());
                                KojiResponse::WriteSignedRpm(result)
                            }
                            KojiRequest::MoveBuild {
                                build_id,
                                expected_sigkey,
                                tag_from,
                                tag_to,
                            } => {
                                let result = bound_client
                                    .call_method1(
                                        "move_build",
                                        (build_id, expected_sigkey, tag_from, tag_to),
                                    )
                                    .context("Koji move_build call failed")
                                    .and_then(|obj| {
                                        obj.extract::<i64>()
                                            .context("Failed to extract move_build task ID")
                                    });
                                KojiResponse::MoveBuild(result)
                            }
                        }
                    });

                    let _ = respond_to.send(response);
                }
                Ok::<_, anyhow::Error>(())
            })
            .context("Failed to spawn Koji request thread")?;

        Ok(Self {
            python_thread,
            request_tx,
            readonly: config.readonly,
        })
    }

    pub fn handle(&self) -> impl KojiOps {
        KojiHandle {
            inner: self.request_tx.clone(),
            readonly: self.readonly,
        }
    }

    pub fn shutdown(self) -> anyhow::Result<()> {
        let thread = self.python_thread;

        // Drop our handle; the thread won't join until all other handles are also dropped.
        let handle = self.request_tx;
        drop(handle);

        thread
            .join()
            .map_err(|error| anyhow::anyhow!("Unable to join python thread: {error:?}"))?
            .context("Python thread did not shut down cleanly")?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct KojiHandle {
    inner: mpsc::Sender<(KojiRequest, oneshot::Sender<KojiResponse>)>,
    readonly: bool,
}

impl KojiOps for KojiHandle {
    #[instrument(skip(self), err)]
    async fn build_info(&self, build_id: i64) -> anyhow::Result<Build> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .send((KojiRequest::BuildInfo { build_id }, tx))
            .await?;

        match rx.await.context("Python actor failed to respond")? {
            KojiResponse::BuildInfo(response) => response,
            other => panic!("Programming error; actor responded with the wrong call: {other:?}"),
        }
    }

    /// Get a chunk of RPMs that have not yet been signed by the provided `sigkey` in the given `tag_name`.
    ///
    /// Returns None when the query returns no more RPMs to sign.
    #[instrument(skip(self), err)]
    async fn rpms_to_sign_in_tag(
        &self,
        tag_name: &str,
        sigkey: &str,
    ) -> anyhow::Result<Option<RpmChunk>> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .send((
                KojiRequest::UnsignedChunk {
                    tag: tag_name.to_owned(),
                    sigkey: sigkey.to_owned(),
                },
                tx,
            ))
            .await?;

        match rx.await.context("Python actor failed to respond")? {
            KojiResponse::UnsignedChunk(response) => response,
            other => panic!("Programming error; actor responded with the wrong call: {other:?}"),
        }
    }

    #[instrument(skip(self), err)]
    async fn add_signature(
        &self,
        rpm_id: i64,
        expected_sigkey: String,
        signed_package: PathBuf,
    ) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .send((
                KojiRequest::AddSignature {
                    rpm_id,
                    expected_sigkey,
                    signed_package,
                },
                tx,
            ))
            .await?;

        match rx.await.context("Python actor failed to respond")? {
            KojiResponse::AddSignature(response) => {
                if self.readonly {
                    tracing::info!(
                        ?response,
                        "Completed Koji add_signature() call, but operating in read-only mode"
                    );
                }
                response
            }
            other => panic!("Programming error; actor responded with the wrong call: {other:?}"),
        }
    }

    #[instrument(skip(self), err)]
    async fn move_build(
        &self,
        build_id: i64,
        expected_sigkey: String,
        tag_from: String,
        tag_to: String,
    ) -> anyhow::Result<i64> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .send((
                KojiRequest::MoveBuild {
                    build_id,
                    expected_sigkey,
                    tag_from,
                    tag_to,
                },
                tx,
            ))
            .await?;

        match rx.await.context("Python actor failed to respond")? {
            KojiResponse::MoveBuild(response) => {
                if self.readonly {
                    tracing::info!(
                        "Completed Koji move_build() call, but operating in read-only mode"
                    );
                }
                response
            }
            other => panic!("Programming error; actor responded with the wrong call: {other:?}"),
        }
    }

    #[instrument(skip(self), err)]
    async fn write_signed_rpm(&self, rpm_id: i64, sigkey: String) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .send((KojiRequest::WriteSignedRpm { rpm_id, sigkey }, tx))
            .await?;

        match rx.await.context("Python actor failed to respond")? {
            KojiResponse::WriteSignedRpm(response) => {
                if self.readonly {
                    tracing::info!(
                        "Completed Koji write_signed_rpm() call, but operating in read-only mode"
                    );
                }
                response
            }
            other => panic!("Programming error; actor responded with the wrong call: {other:?}"),
        }
    }
}
