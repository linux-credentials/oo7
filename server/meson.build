project(
  'oo7-daemon',
  'rust',
  version: '0.1.0',
  meson_version: '>= 1.7',
)

i18n = import('i18n')

is_devel = get_option('profile') == 'development'
dbus_known_name = 'org.freedesktop.secrets'
service_name = meson.project_name()
gettext_package = meson.project_name()

prefix = get_option('prefix')
datadir = get_option('datadir')
dbus_service_dir = get_option('dbus_service_dir')
if dbus_service_dir == ''
  dbus_service_dir = datadir / 'dbus-1' / 'services'
endif
libexecdir = get_option('libexecdir')

build_systemd_service = get_option('systemd')
systemduserunitdir = get_option('systemduserunitdir')
if systemduserunitdir == ''
  systemd = dependency('systemd', version: '>= 242', required: build_systemd_service)
  if build_systemd_service.allowed() and systemd.found()
    if systemduserunitdir == ''
      systemduserunitdir = systemd.get_variable(
        pkgconfig: 'systemduserunitdir',
        pkgconfig_define: ['prefix', prefix]
      )
    endif
  endif
endif

cap_ipc_lock = get_option('cap_ipc_lock')

libexecdir_conf = configuration_data()
libexecdir_conf.set('binary', meson.project_name())
libexecdir_conf.set('libexecdir', prefix / libexecdir)
libexecdir_conf.set('dbus_known_name', dbus_known_name)
libexecdir_conf.set('no_new_privileges', cap_ipc_lock ? 'false' : 'true')
libexecdir_conf.set('private_users', cap_ipc_lock ? 'no' : 'yes')
libexecdir_conf.set('memory_deny_write_execute', cap_ipc_lock ? 'false' : 'true')

summary({
  'prefix': prefix,
  'datadir': datadir,
  'libexecdir': libexecdir,
  'dbus_service_dir': dbus_service_dir,
})

subdir('data')
subdir('src')
subdir('po')
