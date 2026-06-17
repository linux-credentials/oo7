fs = import('fs')

if systemduserunitdir != ''
  service_file = configure_file(
    input: '@0@.service.in'.format(service_name),
    output: '@BASENAME@',
    configuration: libexecdir_conf,
    install_dir: systemduserunitdir,
  )

  install_symlink(
    'dbus-@0@.service'.format(dbus_known_name),
    pointing_to: fs.name(service_file),
    install_dir: systemduserunitdir,
  )
endif
