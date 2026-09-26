fn main() {
    // Allow the Python symbols to be resolved at import time on macOS, like
    // maturin does.
    pyo3_build_config::add_extension_module_link_args();
}
