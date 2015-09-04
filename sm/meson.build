smexe = executable('sm',
	'aci.c', 'dispatch.c', 'feature.c', 'main.c', 'mm.c', 'pkt.c', 'pres.c', 'sess.c', 'sm.c', 'user.c',
	include_directories : inc,
	link_with : [sxlib, miolib, utillib, storagelib],
	link_args : '-ldl',
	dependencies : idn_dep,
	install : true)
