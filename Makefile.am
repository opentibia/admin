bin_PROGRAMS = otadmin


# set the include path found by configure
INCLUDES= $(all_includes)

# the library search path.
otadmin_LDFLAGS = $(all_libraries) -lgmp
otadmin_SOURCES = commands.cpp commands.h definitions.h main.cpp \
		networkmessage.cpp networkmessage.h rsa.cpp rsa.h
