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

cargo_build = custom_target(
  'cargo-build',
  build_by_default: true,
  build_always_stale: true,
  output: [meson.project_name(), 'oo7-daemon-login'],
  console: true,
  install: true,
  install_dir: [libexecdir, libexecdir],
  command: [
    cargo, 'build',
    cargo_options,
    '&&',
    'cp', 'src' / rust_target / meson.project_name(), '@OUTPUT0@',
    '&&',
    'cp', 'src' / rust_target / 'oo7-daemon-login', '@OUTPUT1@',
  ]
)
