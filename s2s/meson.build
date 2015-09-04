s2sexe = executable('s2s',
	'in.c', 'main.c', 'out.c', 'router.c', 'db.c', 'util.c',
	include_directories : inc,
	link_with : [sxlib, miolib],
	dependencies : [idn_dep, udns_dep],
	install : true)
