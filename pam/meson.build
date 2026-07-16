project(
  'oo7-pam',
  'rust',
  version: '0.6.0',
  meson_version: '>= 1.7',
)

is_devel = get_option('profile') == 'development'

prefix = get_option('prefix')
libdir = get_option('libdir')

# PAM modules directory
pam_moduledir = get_option('pam_moduledir')
if pam_moduledir == ''
  pam_moduledir = libdir / 'security'
endif

summary({
  'prefix': prefix,
  'libdir': libdir,
  'libexecdir': get_option('libexecdir'),
  'pam_moduledir': pam_moduledir,
})

subdir('src')
