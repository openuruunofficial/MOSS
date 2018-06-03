ACLOCAL_AMFLAGS = -I aclocal

lib_LTLIBRARIES = libmoss.la libmoss_serv.la

libmoss_la_SOURCES = \
	exceptions.h \
	ConfigParser.h \
	ConfigParser.cc \
	Logger.h \
	Logger.cc \
	machine_arch.h \
	constants.h \
	util.h \
	util.c \
	msg_typecodes.h \
	NetworkMessage.h \
	NetworkMessage.cc \
	MessageQueue.h \
	MessageQueue.cc \
	moss_serv.h \
	moss_serv.cc \
	protocol.h \
	typecodes.h \
	Buffer.h \
	UruString.h \
	UruString.cc \
	VaultNode.h \
	VaultNode.cc \
	backend_typecodes.h \
	BackendMessage.h \
	BackendMessage.cc
EXTRA_libmoss_la_SOURCES = \
	rc4.h \
	rc4.c

libmoss_serv_la_SOURCES = \
	FileTransaction.h \
	FileTransaction.cc \
	AuthServer.h \
	AuthServer.cc \
	AuthMessage.h \
	AuthMessage.cc \
	FileServer.h \
	FileServer.cc \
	FileMessage.h \
	FileMessage.cc \
	PlKey.h \
	PlKey.cc \
	SDL.h \
	SDL.cc \
	GameServer.h \
	GameServer.cc \
	GameMessage.h \
	GameMessage.cc \
	GameState.h \
	GameState.cc \
	GameHandler.h

bin_PROGRAMS = moss moss_backend
if FORK_ENABLE
bin_PROGRAMS += moss_serv
endif

moss_SOURCES = ThreadManager.h dispatcher.cc
if !OLD_PROTOCOL
moss_SOURCES += GatekeeperServer.h GatekeeperServer.cc \
	GatekeeperMessage.h GatekeeperMessage.cc
endif
moss_LDADD = libmoss.la libmoss_serv.la -lz -lpthread @ssl_libs@

moss_backend_SOURCES = moss_backend.h moss_backend.cc backend_all.cc \
	db_requests.h db_requests.cc
moss_backend_LDADD = libmoss.la -lpthread @ssl_libs@ @db_libs@

moss_serv_SOURCES = moss_child.cc
moss_serv_LDADD = libmoss.la libmoss_serv.la -lz -lpthread @ssl_libs@

if !HAVE_OPENSSL
libmoss_la_SOURCES += $(EXTRA_libmoss_la_SOURCES)
endif

if USING_DH
bin_PROGRAMS += make_cyan_dh
endif
if USING_RSA
bin_PROGRAMS += rsa_convert
endif
bin_PROGRAMS += global_sdl_manager

make_cyan_dh_SOURCES = support/make_cyan_dh.c
make_cyan_dh_LDADD = @ssl_libs@
rsa_convert_SOURCES = support/rsa_convert.c
rsa_convert_LDADD = @ssl_libs@
global_sdl_manager_SOURCES = support/global_sdl_manager.cc
global_sdl_manager_LDADD = db_requests.o libmoss.la libmoss_serv.la \
	-lz @db_libs@

EXTRA_DIST = bootstrap.sh main.cfg example_game_only.cfg backend.cfg \
	postgresql doc/setup doc/running doc/user-management \
	support/make-mbam.pl support/update-mbm.pl support/set_to_moul.txt \
	support/sharperjournal.sql support/welcome-laxman.sql \
	support/gzimager-moul.sql test/reftree.sql \
	support/Manifests.zip support/macExternal.txt \
	support/ManifestCreator support/ManifestCreator.exe

# XXX disable these on Windows
EXTRA_PROGRAMS = ntd UruString_tester pcap_replay sdl_reader \
	TimerQueue_tester age_reader
if !USING_DH
EXTRA_PROGRAMS += make_cyan_dh
endif
if !USING_RSA
EXTRA_PROGRAMS += rsa_convert
endif
if HAVE_OPENSSL
EXTRA_PROGRAMS += compute_auth_hash
compute_auth_hash_SOURCES = support/compute_auth_hash.c
compute_auth_hash_LDADD = @ssl_libs@
endif
ntd_SOURCES = support/ntd.c
ntd_LDADD =
UruString_tester_SOURCES = test/UruString_tester.cc
UruString_tester_CXXFLAGS = -DTEST_CODE
UruString_tester_LDADD = UruString.o
pcap_replay_SOURCES = test/pcap_replay.c
pcap_replay_LDADD = -lpcap
sdl_reader_SOURCES = test/sdl_reader.cc
sdl_reader_LDADD = libmoss_serv.la libmoss.la -lz @ssl_libs@
TimerQueue_tester_SOURCES = test/TimerQueue_tester.cc
TimerQueue_tester_LDADD = libmoss_serv.la libmoss.la -lz @ssl_libs@
age_reader_SOURCES = test/age_reader.cc
age_reader_LDADD = libmoss_serv.la libmoss.la -lz @ssl_libs@

clean-local:
	-rm -f $(EXTRA_PROGRAMS)
