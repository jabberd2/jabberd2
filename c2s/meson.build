c2sexe = executable('c2s',
	'authreg.c', 'bind.c', 'c2s.c', 'main.c', 'sm.c', 'pbx.c', 'pbx_commands.c', 'address.c',
	include_directories : [inc, include_directories('.')],
	link_with : [miolib, sxlib],
	link_args : '-ldl',
	dependencies : idn_dep,
	install : true)
