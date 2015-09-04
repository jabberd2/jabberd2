routerexe = executable('router',
	'aci.c', 'main.c', 'router.c', 'user.c', 'filter.c',
	include_directories : inc,
	link_with : [sxlib, miolib],
	dependencies : idn_dep,
	install : true)
