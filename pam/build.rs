use std::env::var_os;

fn main() {
    if var_os("DOCS_RS").is_some() {
        // libpam isn't available on docs.rs, and we don't need to link
        // against it to build the documentation.
        return;
    }

    println!("cargo::rustc-link-lib=pam");
}
