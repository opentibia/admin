dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([otadmin],[0.1.0])
AC_CONFIG_SRCDIR([rsa.h])
AM_INIT_AUTOMAKE([foreign])

AC_REVISION($Revision: 1.0 $)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_LANG(C++)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])
#
AC_FUNC_MALLOC
AC_FUNC_REALLOC
#
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([getenv])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T

#check GMP
AC_CHECK_HEADERS([gmp.h], ,[AC_MSG_ERROR("*** GMP header not found.")])
AC_CHECK_LIB(gmp, __gmpz_init2, ,[AC_MSG_ERROR("*** GMP library not found or < 4.0.")])

# output files
AC_CONFIG_FILES([
	Makefile
])

AC_OUTPUT
