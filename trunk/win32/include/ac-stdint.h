#ifndef _AC_STDINT_H
#define _AC_STDINT_H 1
#ifndef _GENERATED_STDINT_H
#define _GENERATED_STDINT_H

#define uint8_t		unsigned char
#define uint16_t	unsigned short
#define uint32_t	unsigned int
#define int8_t		signed char
#define int16_t		signed short
#define int32_t		signed int

#define gint16		int16_t

#ifdef  _WIN64
typedef __int64		ssize_t;
#else
typedef _W64 int	ssize_t;
#endif

#endif
#endif
