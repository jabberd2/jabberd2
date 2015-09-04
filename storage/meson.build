
storagelib = static_library('storage',
	'storage.c', 'object.c',
	include_directories : inc)

authregsqlitelib = shared_library('authreg_sqlite',
	'authreg_sqlite.c',
	include_directories : [inc, include_directories('../c2s')],
	dependencies : sqlite_dep)

storagesqlitelib = shared_library('storage_sqlite',
	'storage_sqlite.c',
	include_directories : inc,
	dependencies : sqlite_dep)
