xlator_LTLIBRARIES = metadata.la
xlatordir = $(libdir)/zefs/$(PACKAGE_VERSION)/xlator/performance

metadata_la_LDFLAGS = -module -avoid-version

metadata_la_SOURCES = metadata.c metadata-helper.c
metadata_la_LIBADD = $(top_builddir)/libzefs/src/libzefs.la

noinst_HEADERS = metadata.h metadata-mem-types.h

AM_CPPFLAGS = $(GF_CPPFLAGS) \
	-I$(top_srcdir)/libzefs/src -I$(top_srcdir)/rpc/xdr/src \
	-I$(top_srcdir)/rpc/rpc-lib/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES =
