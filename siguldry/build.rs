use std::env;
use std::path::PathBuf;

fn main() {
    #[cfg(feature = "rpm")]
    {
        println!("cargo:rustc-link-lib=rpm");
        println!("cargo:rustc-link-lib=rpmio");

        let bindings = bindgen::Builder::default()
            .header("wrapper.h")
            .allowlist_item("Fclose")
            .allowlist_item("Fopen")
            .allowlist_item("headerFree")
            .allowlist_item("headerGet")
            .allowlist_item("headerGetNumber")
            .allowlist_item("rpmLeadRead")
            .allowlist_item("rpmLeadWrite")
            .allowlist_item("rpmReadSignature")
            .allowlist_item("rpmfiFDigest")
            .allowlist_item("rpmfiFSize")
            .allowlist_item("rpmfiBN")
            .allowlist_item("rpmfiDN")
            .allowlist_item("rpmfiDigestAlgo")
            .allowlist_item("rpmfiFC")
            .allowlist_item("rpmfiFlags_e")
            .allowlist_item("rpmfiFree")
            .allowlist_item("rpmfiNew")
            .allowlist_item("rpmfiNext")
            .allowlist_item("rpmReadPackageFile")
            .allowlist_item("rpmTag_e")
            .allowlist_item("rpmtdFree")
            .allowlist_item("rpmtdNew")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .expect("Unable to generate librpm bindings");
        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
