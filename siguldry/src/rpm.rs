mod sys {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

struct RpmFileInfo(sys::rpmfi);

impl RpmFileInfo {
    fn new(header: &Header) -> Result<Self, anyhow::Error> {
        // Refer to RPMFI_FLAGS_QUERY
        let flags = rpmfiFlags_e_RPMFI_NOFILECLASS
            | rpmfiFlags_e_RPMFI_NOFILEDEPS
            | rpmfiFlags_e_RPMFI_NOFILELANGS
            | rpmfiFlags_e_RPMFI_NOFILECOLORS
            | rpmfiFlags_e_RPMFI_NOFILEVERIFYFLAGS;
        // Documentation indicates tagN is unused, but this matches the query used by
        // rpmsign just in case the docs aren't being honest with us.
        let fi = unsafe {
            sys::rpmfiNew(
                ptr::null_mut(),
                header.as_ptr(),
                rpmTag_e_RPMTAG_BASENAMES,
                flags,
            )
        };
        if fi.is_null() {
            anyhow::bail!("failed to allocate new RPM file info object");
        }

        Ok(Self(fi))
    }

    fn file_count(&self) -> usize {
        unsafe {sys::rpmfiFC(self.0) as usize}
    }

    fn digest_algorithm (&self) -> i32 {
        // TODO add native enum with digest sizes
        unsafe {sys::rpmfiDigestAlgo(self.0)}
    }
}

impl Iterator for RpmFileInfo {
    type Item = RpmFile;

    fn next(&mut self) -> Option<Self::Item> {
        let status = unsafe{sys::rpmfiNext(self.0)};
        if status < 0 {
            None
        } else {
            let mut digest_algorithm = MaybeUninit::<std::ffi::c_int>::uninit();
            let mut digest_length = MaybeUninit::<libc::size_t>::uninit();
            let digest = unsafe {sys::rpmfiFDigest(self.0, digest_algorithm.as_mut_ptr(), digest_length.as_mut_ptr())};
            let basename = unsafe { sys::rpmfiBN(self.0 )};
            let dirname = unsafe { sys::rpmfiDN(self.0 )};
            let path = if !basename.is_null() && !dirname.is_null() {
                let base = unsafe {CStr::from_ptr(basename)};
                let dir = unsafe {CStr::from_ptr(dirname)};
                let mut absolute_path = PathBuf::from(dir.to_string_lossy().to_string());
                absolute_path.push(base.to_string_lossy().to_string());
                println!("path is {absolute_path:?}");
                Some(absolute_path)
            } else {
                None
            };
            if digest.is_null() {
                None
            } else {
                let digest_algorithm = unsafe {digest_algorithm.assume_init()} ;
                let digest_length= unsafe {digest_length.assume_init()};
                let digest = unsafe { slice::from_raw_parts(digest, digest_length) };
                let digest = Vec::from(digest);
                println!("{digest_algorithm} algo is {digest_length}: {digest:x?}");
                Some(RpmFile {
                    digest_algorithm,
                    path,
                    digest,
                })
            }
        }
    }
}

impl Drop for RpmFileInfo {
    fn drop(&mut self) {
        unsafe {
            sys::rpmfiFree(self.0);
        }
    }
}

struct RpmFile {
    digest_algorithm: i32,
    digest: Vec<u8>,
    path: Option<PathBuf>,
}

struct RpmTagData(sys::rpmtd);

impl RpmTagData {
    fn new() -> Result<Self, anyhow::Error> {
        let td = unsafe { sys::rpmtdNew() };
        if td.is_null() {
            anyhow::bail!("failed to allocate new RPM td (what is a td?)");
        }

        Ok(Self(td))
    }

    fn data(&self) -> Option<(*const u8, usize)> {
        let rpmtd = unsafe { *self.0 };
        if rpmtd.data.is_null() || rpmtd.size < 1 {
            None
        } else {
            Some((rpmtd.data as *const u8, rpmtd.size as usize))
        }
    }

    fn as_ptr(&self) -> sys::rpmtd {
        self.0
    }
}

impl Drop for RpmTagData {
    fn drop(&mut self) {
        unsafe {
            sys::rpmtdFree(self.0);
        }
    }
}

struct Header(sys::Header);

impl Header {
    fn from_package(package: &Path) -> Result<Self, anyhow::Error> {
        let path = CString::new(package.as_os_str().as_bytes())?;
        let fd = unsafe { sys::Fopen(path.as_ptr(), c"r.ufdio".as_ptr()) };
        if fd.is_null() {
            let os_error = std::io::Error::last_os_error();
            anyhow::bail!("failed to open RPM at {package:?}: {os_error:?}");
        }

        let mut header = MaybeUninit::<sys::Header>::uninit();
        let status = unsafe {
            sys::rpmReadPackageFile(
                ptr::null_mut(),
                fd,
                c"apparently-uneeded".as_ptr(),
                header.as_mut_ptr(),
            )
        };
        let close_status = unsafe { sys::Fclose(fd) };
        if status != sys::rpmRC_e_RPMRC_OK {
            anyhow::bail!("Failed to read RPM header from package file");
        }

        // SAFETY: When rpmReadPackageFile returns success, the header pointer is initialized.
        let header_ptr: sys::Header = unsafe { header.assume_init() };

        Ok(Self(header_ptr))
    }

    fn file_digest_algorithm(&self) -> u64 {
        // SAFETY: The pointer is private and guaranteed to be valid during the lifetime of
        // the object, and is never modified.
        unsafe { sys::headerGetNumber(self.0, sys::rpmTag_e_RPMTAG_FILEDIGESTALGO) }
    }

    // This part of the header is what should be PGP-signed.
    fn immutable_header(&self) -> Result<Vec<u8>, anyhow::Error> {
        let td = RpmTagData::new()?;

        let status =
            unsafe { sys::headerGet(self.0, sys::rpmTag_e_RPMTAG_HEADERIMMUTABLE, td.as_ptr(), 0) };
        if status == 0 {
            anyhow::bail!("failed to extract RPM tag data");
        }
        if let Some((raw_data_ptr, data_size)) = td.data() {
            let data = unsafe { slice::from_raw_parts(raw_data_ptr, data_size) };
            Ok(Vec::from(data))
        } else {
            anyhow::bail!("Failed to extract immutable header")
        }
    }

    fn file_digests(&self) -> Result<Vec<String>, anyhow::Error> {
        let td = RpmTagData::new()?;

        Ok(vec![])
    }

    fn as_ptr(&self) -> sys::Header {
        self.0
    }
}

impl Drop for Header {
    fn drop(&mut self) {
        unsafe {
            sys::headerFree(self.0);
        }
    }
}

use core::slice;
use std::{
    ffi::{CStr, CString},
    mem::MaybeUninit,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{self, NonNull},
};

use bytes::{Buf, Bytes};

use crate::rpm::sys::{
    rpmTag_e_RPMTAG_BASENAMES, rpmfiFlags_e_RPMFI_KEEPHEADER, rpmfiFlags_e_RPMFI_NOFILECLASS,
    rpmfiFlags_e_RPMFI_NOFILECOLORS, rpmfiFlags_e_RPMFI_NOFILEDEPS, rpmfiFlags_e_RPMFI_NOFILELANGS,
    rpmfiFlags_e_RPMFI_NOFILEVERIFYFLAGS,
};
/// Utilities for extracting bits and pieces from RPMs.
///
/// Refer to https://rpm.org/docs/6.0.x/manual/format_v4.html
/// and https://rpm.org/docs/6.0.x/manual/format_v6.html.
///
/// Note, as the docs say, the proper way to access these structures are through
/// librpm. Unfortunately librpm provides fairly lackluster APIs and they've been
/// explict they expect everyone to use their rpmsign CLI to sign things.

const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];

struct Lead {
    magic: [u8; 4],
    rest: [u8; 92],
}

const HEADER_MAGIC: Bytes = Bytes::from_static(&[0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00]);

// https://rpm.org/docs/6.0.x/manual/format_header.html
struct OldeHeader {
    magic: [u8; 8],
    index_length: u32, // stored as network order bytes; each index is a tag, type, offset and count (total 16 bytes)
    data_length: u32,  // stored as network order bytes
}

fn parse(rpm: &[u8]) -> anyhow::Result<Bytes> {
    let mut bytes = Bytes::copy_from_slice(rpm);
    if bytes.len() < (96 + 16) {
        anyhow::bail!("Not even big enough for a lead");
    }
    let lead = bytes.split_to(96);

    let mut sig_header = bytes.split_to(16);
    if sig_header.split_to(8) != HEADER_MAGIC {
        anyhow::bail!("header magic wrong");
    }
    let index_length = sig_header.get_u32();
    let data_length = sig_header.get_u32();
    let sig_length = (index_length * 16) + data_length;
    let sig_length = (sig_length + (8 - (sig_length % 8)) % 8) as usize;

    if bytes.len() < sig_length + 8 {
        anyhow::bail!("No sig")
    }
    bytes.split_to(sig_length);

    // now for the interesting header
    if !bytes.starts_with(&HEADER_MAGIC) {
        anyhow::bail!("header magic wrong");
    }
    let index_length = bytes.slice(8..12).get_u32();
    let data_length = bytes.slice(12..16).get_u32();
    let header_length = ((index_length * 16) + data_length) as usize;

    if bytes.len() < header_length {
        anyhow::bail!("No header");
    }

    // This should be, in theory, the thing we sign. It also includes the
    // file list which we need to extract.
    let header = bytes.split_to(header_length + 16);

    Ok(header)
}

fn header_size(rpm: Vec<u8>) {
    // Koji's size algorithm:

    // 3 bytes of magic, 1 byte version number, 4 bytes reserved.
    let magic = 8;
    let lead_size = 96;

    // Read two 4-byte integers (network byte order) which are
    // - index_entries: number of index entries
    // - data_length: bytes of data in header

    // then header_size is 8 + (16 * index_entries) + data_length

    // the signature header is padded, so header_size = header_size + (8 - (header_size % 8)) % 8
    // finally, add 8 bytes for section header
}

fn sign_files() {
    // get a list of files and their digests from RPM;
    // some items in the list (directories, symlinks, etc) do not have a digest.
    //    for these, do what rpmsignfiles.c does: return ""
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use super::*;

    #[test]
    fn from_valid_package() {
        let path = PathBuf::from("/home/jcline/Downloads/binutils-2.45.50-11.fc44.x86_64.rpm");
        let header = Header::from_package(&path).unwrap();
        let algo = header.file_digest_algorithm();
        assert_eq!(algo, 8);

        let immutable_header = header.immutable_header().unwrap();
        assert_eq!(immutable_header.len(), 56_821);

        let file_digests = RpmFileInfo::new(&header).unwrap().collect::<Vec<_>>();
        assert_eq!(file_digests.len(), 250);
        for file in file_digests {
            println!("{:x?} ({})", file.digest, file.path.unwrap_or_else(PathBuf::new).display());
        }
    }

    #[test]
    fn from_package_no_such_file() {
        let path = PathBuf::from("/this/path/does/not/exist.rpm");
        let header = Header::from_package(&path).unwrap();
        let algo = header.file_digest_algorithm();
        assert_eq!(algo, 8);
    }

    #[test]
    fn read_rpm() {
        let f =
            std::fs::read("/home/jcline/Downloads/binutils-2.45.50-11.fc44.x86_64.rpm").unwrap();

        let header = parse(&f).unwrap();

        let f = std::fs::write(
            "/home/jcline/binutils-2.45.50-11.fc44.x86_64.rpm.headers",
            header,
        )
        .unwrap();
    }
}
