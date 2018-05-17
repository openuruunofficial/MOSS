# before 9.1 you just built a module
MODULES = moss_uuidgen

# 9.1 and later you build an extension
EXTENSION = moss_uuidgen
DATA = moss_uuidgen--1.0.sql

PGXS := $(shell pg_config --pgxs)
include $(PGXS)
