cargo = find_program('cargo')

cargo_options = []
cargo_options += [ '--target-dir', meson.project_build_root() / 'src' ]
if is_devel
  rust_target = 'debug'
  message('Building in debug mode')
else
  cargo_options += [ '--release' ]
  rust_target = 'release'
  message('Building in release mode')
endif

pam_module_name = 'pam_oo7.so'
helper_path = get_option('prefix') / get_option('libexecdir') / 'oo7-daemon-login'

cargo_build = custom_target(
  'cargo-build',
  build_by_default: true,
  build_always_stale: true,
  output: pam_module_name,
  console: true,
  install: true,
  install_dir: pam_moduledir,
  env: {'OO7_DAEMON_LOGIN_PATH': helper_path},
  command: [
    cargo, 'build',
    cargo_options,
    '&&',
    'cp', 'src' / rust_target / 'libpam_oo7.so', '@OUTPUT@',
  ]
)
