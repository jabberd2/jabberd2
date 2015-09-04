sxlib = static_library('sx',
	'callback.c', 'chain.c', 'client.c', 'env.c', 'error.c', 'io.c', 'server.c', 'sx.c', 'sasl.c', 'ack.c', 'ssl.c', 'compress.c', 'websocket.c',
	include_directories : inc,
	dependencies : [expat_dep, gsasl_dep, ssl_dep, zlib_dep, http_parser_dep],
	link_with : utillib)
