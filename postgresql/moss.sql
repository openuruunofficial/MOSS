-- MOSS - A server for the Myst Online: Uru Live client/protocol
-- Copyright (C) 2008-2011  cjkelly1 and a'moaca'
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.


--
-- PostgreSQL database dump
--

SET client_encoding = 'UTF8';
SET standard_conforming_strings = off;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET escape_string_warning = off;

--
-- Name: plpgsql; Type: PROCEDURAL LANGUAGE; Schema: -; Owner: postgres
--

CREATE PROCEDURAL LANGUAGE plpgsql;


ALTER PROCEDURAL LANGUAGE plpgsql OWNER TO postgres;

SET search_path = public, pg_catalog;

--
-- Name: uuid(); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION uuid() RETURNS text
    AS 'moss_uuidgen', 'moss_uuidgen_text'
    LANGUAGE c STRICT;


ALTER FUNCTION public.uuid() OWNER TO moss;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: accounts; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE accounts (
    name character varying(64) NOT NULL,
    email character varying,
    hash character(40),
    id character(36) DEFAULT uuid(),
    class character varying,
    visitor boolean,
    banned boolean DEFAULT false
);


ALTER TABLE public.accounts OWNER TO moss;

--
-- Name: admin; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE admin (
    name character varying(64) NOT NULL,
    createtime timestamp without time zone DEFAULT now(),
    modifytime timestamp without time zone,
    uuid_1 character(36)
);


ALTER TABLE public.admin OWNER TO moss;

--
-- Name: TABLE admin; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE admin IS '* unused? *';


--
-- Name: COLUMN admin.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN admin.createtime IS 'CreateTime (0x00000002)';


--
-- Name: age; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE age (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    creatoracctid character(36),
    creatorid numeric(10,0),
    uuid_1 character(36),
    uuid_2 character(36),
    filename text
);


ALTER TABLE public.age OWNER TO moss;

--
-- Name: TABLE age; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE age IS 'Node type 0x03';


--
-- Name: COLUMN age.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN age.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN age.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN age.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN age.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN age.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN age.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN age.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN age.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN age.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN age.uuid_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN age.uuid_1 IS 'UUID_1 (0x00010000)';


--
-- Name: COLUMN age.uuid_2; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN age.uuid_2 IS 'UUID_2 (0x00020000)';


--
-- Name: COLUMN age.filename; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN age.filename IS 'String64_1 (0x00100000)';


--
-- Name: ageinfo; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE ageinfo (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    creatoracctid character(36),
    creatorid numeric(10,0),
    int32_1 numeric(10,0),
    int32_2 numeric(10,0),
    int32_3 numeric(10,0),
    uint32_1 numeric(10,0),
    uint32_2 numeric(10,0),
    uint32_3 numeric(10,0),
    uuid_1 character(36),
    uuid_2 character(36),
    string64_2 text,
    string64_3 text,
    string64_4 text,
    text_1 text
);


ALTER TABLE public.ageinfo OWNER TO moss;

--
-- Name: TABLE ageinfo; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE ageinfo IS 'Node type 0x21';


--
-- Name: COLUMN ageinfo.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN ageinfo.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN ageinfo.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN ageinfo.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN ageinfo.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN ageinfo.int32_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.int32_1 IS 'Int32_1 (0x00000100)';


--
-- Name: COLUMN ageinfo.int32_2; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.int32_2 IS 'Int32_2 (0x00000200)';


--
-- Name: COLUMN ageinfo.int32_3; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.int32_3 IS 'Int32_3 (0x00000400)';


--
-- Name: COLUMN ageinfo.uint32_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.uint32_1 IS 'UInt32_1 (0x00001000)';


--
-- Name: COLUMN ageinfo.uint32_2; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.uint32_2 IS 'UInt32_2 (0x00002000)';


--
-- Name: COLUMN ageinfo.uint32_3; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.uint32_3 IS 'UInt32_3 (0x00004000)';


--
-- Name: COLUMN ageinfo.uuid_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.uuid_1 IS 'UUID_1 (0x00010000)';


--
-- Name: COLUMN ageinfo.uuid_2; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.uuid_2 IS 'UUID_2 (0x00020000)';


--
-- Name: COLUMN ageinfo.string64_2; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.string64_2 IS 'String64_2 (0x00200000)';


--
-- Name: COLUMN ageinfo.string64_3; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.string64_3 IS 'String64_3 (0x00400000)';


--
-- Name: COLUMN ageinfo.string64_4; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.string64_4 IS 'String64_4 (0x00800000)';


--
-- Name: COLUMN ageinfo.text_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfo.text_1 IS 'Text_1 (0x10000000)';


--
-- Name: ageinfolist; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE ageinfolist (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    creatoracctid character(36),
    creatorid numeric(10,0),
    type integer
);


ALTER TABLE public.ageinfolist OWNER TO moss;

--
-- Name: TABLE ageinfolist; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE ageinfolist IS 'Node type 0x22';


--
-- Name: COLUMN ageinfolist.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfolist.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN ageinfolist.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfolist.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN ageinfolist.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfolist.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN ageinfolist.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfolist.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN ageinfolist.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfolist.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN ageinfolist.type; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ageinfolist.type IS 'Int32_1 (0x00000100)';


--
-- Name: agelink; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE agelink (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    createageuuid character(36),
    createagename text,
    creatoracctid character(36),
    creatorid numeric(10,0),
    shared numeric(10,0),
    volatile numeric(10,0),
    linkpoints bytea
);


ALTER TABLE public.agelink OWNER TO moss;

--
-- Name: TABLE agelink; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE agelink IS 'Node type 0x1c';


--
-- Name: COLUMN agelink.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN agelink.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN agelink.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN agelink.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN agelink.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN agelink.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN agelink.createageuuid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN agelink.createageuuid IS 'CreateAgeUUID (0x00000010)';


--
-- Name: COLUMN agelink.createagename; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN agelink.createagename IS 'CreateAgeName (0x00000008)';


--
-- Name: COLUMN agelink.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN agelink.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN agelink.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN agelink.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN agelink.shared; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN agelink.shared IS 'Int32_1 (0x00000100)';


--
-- Name: COLUMN agelink.volatile; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN agelink.volatile IS 'Int32_2 (0x00000200)';


--
-- Name: COLUMN agelink.linkpoints; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN agelink.linkpoints IS 'Blob_1 (0x40000000)';


--
-- Name: ccr; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE ccr (
    nodeid numeric(10,0) NOT NULL
);


ALTER TABLE public.ccr OWNER TO moss;

--
-- Name: TABLE ccr; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE ccr IS '* unused? *';


--
-- Name: COLUMN ccr.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN ccr.nodeid IS 'NodeID (0x00000001)';


--
-- Name: chronicle; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE chronicle (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    createageuuid character(36),
    createagename text,
    creatoracctid character(36),
    creatorid numeric(10,0),
    type integer,
    name text,
    value text
);


ALTER TABLE public.chronicle OWNER TO moss;

--
-- Name: TABLE chronicle; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE chronicle IS 'Node type 0x1d';


--
-- Name: COLUMN chronicle.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN chronicle.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN chronicle.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN chronicle.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN chronicle.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN chronicle.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN chronicle.createageuuid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN chronicle.createageuuid IS 'CreateAgeUUID (0x00000010)';


--
-- Name: COLUMN chronicle.createagename; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN chronicle.createagename IS 'CreateAgeName (0x00000008)';


--
-- Name: COLUMN chronicle.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN chronicle.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN chronicle.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN chronicle.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN chronicle.type; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN chronicle.type IS 'Int32_1 (0x00000100)';


--
-- Name: COLUMN chronicle.name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN chronicle.name IS 'String64_1 (0x00100000)';


--
-- Name: COLUMN chronicle.value; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN chronicle.value IS 'Text_1 (0x10000000)';


--
-- Name: connected; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE connected (
    id numeric(10,0) NOT NULL
);


ALTER TABLE public.connected OWNER TO moss;

--
-- Name: TABLE connected; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE connected IS 'List of active players';


--
-- Name: COLUMN connected.id; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN connected.id IS 'KI number';


--
-- Name: folder; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE folder (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    createageuuid character(36),
    createagename text,
    creatoracctid character(36),
    creatorid numeric(10,0),
    type integer,
    name text
);


ALTER TABLE public.folder OWNER TO moss;

--
-- Name: TABLE folder; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE folder IS 'Node type 0x16';


--
-- Name: COLUMN folder.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN folder.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN folder.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN folder.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN folder.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN folder.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN folder.createageuuid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN folder.createageuuid IS 'CreateAgeUUID (0x00000010)';


--
-- Name: COLUMN folder.createagename; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN folder.createagename IS 'CreateAgeName (0x00000008)';


--
-- Name: COLUMN folder.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN folder.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN folder.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN folder.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN folder.type; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN folder.type IS 'Int32_1 (0x00000100)';


--
-- Name: COLUMN folder.name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN folder.name IS 'String64_1 (0x00100000)';


--
-- Name: gameserver; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE gameserver (
    nodeid numeric(10,0) NOT NULL
);


ALTER TABLE public.gameserver OWNER TO moss;

--
-- Name: TABLE gameserver; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE gameserver IS '* unused ? *';


--
-- Name: COLUMN gameserver.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN gameserver.nodeid IS 'NodeID (0x00000001)';


--
-- Name: image; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE image (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    createageuuid character(36),
    createagename text,
    creatoracctid character(36),
    creatorid numeric(10,0),
    "exists" integer,
    name text,
    image bytea
);


ALTER TABLE public.image OWNER TO moss;

--
-- Name: TABLE image; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE image IS 'Node type 0x19';


--
-- Name: COLUMN image.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN image.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN image.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN image.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN image.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN image.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN image.createageuuid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN image.createageuuid IS 'CreateAgeUUID (0x00000010)';


--
-- Name: COLUMN image.createagename; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN image.createagename IS 'CreateAgeName (0x00000008)';


--
-- Name: COLUMN image.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN image.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN image.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN image.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN image."exists"; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN image."exists" IS 'Int32_1 (0x00000100)';


--
-- Name: COLUMN image.name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN image.name IS 'String64_1 (0x00100000)';


--
-- Name: COLUMN image.image; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN image.image IS 'Blob_1 (0x40000000)';


--
-- Name: markergame; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE markergame (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    createageuuid character(36),
    createagename text,
    creatoracctid character(36),
    creatorid numeric(10,0),
    name text,
    uuid_1 character(36)
);


ALTER TABLE public.markergame OWNER TO moss;

--
-- Name: TABLE markergame; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE markergame IS 'Node type 0x23 - (called MarkerListNode in UU/PotS)';


--
-- Name: COLUMN markergame.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markergame.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN markergame.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markergame.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN markergame.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markergame.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN markergame.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markergame.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN markergame.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markergame.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN markergame.name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markergame.name IS 'Text_1 (0x10000000)';


--
-- Name: COLUMN markergame.uuid_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markergame.uuid_1 IS 'UUID_1 (0x00010000)';


--
-- Name: markers; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE markers (
    game_id numeric(10,0) NOT NULL,
    x double precision,
    y double precision,
    z double precision,
    marker_number numeric NOT NULL,
    marker_name text,
    age_name text
);


ALTER TABLE public.markers OWNER TO moss;

--
-- Name: TABLE markers; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE markers IS 'Table for all marker locations';


--
-- Name: COLUMN markers.game_id; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markers.game_id IS 'template internal ID';


--
-- Name: COLUMN markers.x; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markers.x IS 'X location';


--
-- Name: COLUMN markers.y; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markers.y IS 'Y location';


--
-- Name: COLUMN markers.z; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markers.z IS 'Z location';


--
-- Name: COLUMN markers.marker_number; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markers.marker_number IS 'the marker number';


--
-- Name: COLUMN markers.marker_name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markers.marker_name IS 'the name of the marker';


--
-- Name: COLUMN markers.age_name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markers.age_name IS 'which age the marker is in';


--
-- Name: markersinplay; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE markersinplay (
    game_id numeric(10,0) NOT NULL,
    player numeric(10,0) NOT NULL,
    marker_number numeric(10,0) NOT NULL,
    value numeric(10,0)
);


ALTER TABLE public.markersinplay OWNER TO moss;

--
-- Name: TABLE markersinplay; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE markersinplay IS 'Makers for current active games';


--
-- Name: COLUMN markersinplay.game_id; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markersinplay.game_id IS 'template internal ID';


--
-- Name: COLUMN markersinplay.player; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markersinplay.player IS 'the game player';


--
-- Name: COLUMN markersinplay.marker_number; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markersinplay.marker_number IS 'which age the marker is in';


--
-- Name: COLUMN markersinplay.value; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markersinplay.value IS 'marker capture value';


--
-- Name: markertemplate_seq; Type: SEQUENCE; Schema: public; Owner: moss
--

CREATE SEQUENCE markertemplate_seq
    INCREMENT BY 1
    MAXVALUE 9999999999
    MINVALUE 100
    CACHE 1;


ALTER TABLE public.markertemplate_seq OWNER TO moss;

--
-- Name: SEQUENCE markertemplate_seq; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON SEQUENCE markertemplate_seq IS 'This sequence is for generating db-internal marker game template IDs';


--
-- Name: markertemplate_seq; Type: SEQUENCE SET; Schema: public; Owner: moss
--

SELECT pg_catalog.setval('markertemplate_seq', 100, true);


--
-- Name: markertemplates; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE markertemplates (
    game_id numeric(10,0) DEFAULT nextval('markertemplate_seq'::regclass) NOT NULL,
    uuid character(36) NOT NULL,
    owner numeric(10,0),
    type numeric(4,0),
    name text,
    next_number integer DEFAULT 0
);


ALTER TABLE public.markertemplates OWNER TO moss;

--
-- Name: TABLE markertemplates; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE markertemplates IS 'Table for template UUID <-> internal ID';


--
-- Name: COLUMN markertemplates.game_id; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markertemplates.game_id IS 'template internal ID';


--
-- Name: COLUMN markertemplates.uuid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markertemplates.uuid IS 'template UUID';


--
-- Name: COLUMN markertemplates.owner; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markertemplates.owner IS 'player who created the game';


--
-- Name: COLUMN markertemplates.name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markertemplates.name IS 'the name of the game';


--
-- Name: COLUMN markertemplates.next_number; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN markertemplates.next_number IS 'the next marker number to use';


--
-- Name: noderefs; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE noderefs (
    parent numeric(10,0) NOT NULL,
    child numeric(10,0) NOT NULL,
    ownerid numeric(10,0) DEFAULT 0 NOT NULL,
    notifier numeric(10,0) DEFAULT 0 NOT NULL
);


ALTER TABLE public.noderefs OWNER TO moss;

--
-- Name: COLUMN noderefs.ownerid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN noderefs.ownerid IS 'Not null and default to 0.  Assuming all noderefs should have an owner.';


--
-- Name: COLUMN noderefs.notifier; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN noderefs.notifier IS 'Not null and default to 0.  This is kind of what we think ownerid should have been (and 0 means no dynamic notification will occur).';


--
-- Name: nodeid_seq; Type: SEQUENCE; Schema: public; Owner: moss
--

CREATE SEQUENCE nodeid_seq
    INCREMENT BY 1
    MAXVALUE 9999999999
    MINVALUE 100
    CACHE 1;


ALTER TABLE public.nodeid_seq OWNER TO moss;

--
-- Name: SEQUENCE nodeid_seq; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON SEQUENCE nodeid_seq IS 'This sequence is for generating node IDs which will be unique across all vault node tables.  In order to set a field in a table to use it (like an autoincrement), use the following line as the default value:

nextval(''nodeid_seq''::regclass)

(note: we set minimum and current initial values to 100, so nextval will return 101 when used)';


--
-- Name: nodeid_seq; Type: SEQUENCE SET; Schema: public; Owner: moss
--

SELECT pg_catalog.setval('nodeid_seq', 100, true);


--
-- Name: nodes; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE nodes (
    nodeid numeric(10,0) DEFAULT nextval('nodeid_seq'::regclass) NOT NULL,
    type integer
);


ALTER TABLE public.nodes OWNER TO moss;

--
-- Name: TABLE nodes; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE nodes IS 'This table contains a master list of nodes and their types.';


--
-- Name: player; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE player (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    creatoracctid character(36),
    creatorid numeric(10,0),
    int32_1 numeric(10,0),
    int32_2 numeric(10,0),
    uint32_1 numeric(10,0),
    uuid_1 character(36),
    uuid_2 character(36),
    gender text,
    name text
);


ALTER TABLE public.player OWNER TO moss;

--
-- Name: TABLE player; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE player IS 'Node type 0x02';


--
-- Name: COLUMN player.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN player.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN player.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN player.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN player.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN player.int32_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.int32_1 IS 'Int32_1 (0x00000100)';


--
-- Name: COLUMN player.int32_2; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.int32_2 IS 'Int32_2 (0x00000200)';


--
-- Name: COLUMN player.uint32_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.uint32_1 IS 'UInt32_1 (0x00001000)';


--
-- Name: COLUMN player.uuid_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.uuid_1 IS 'UUID_1 (0x00010000)';


--
-- Name: COLUMN player.uuid_2; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.uuid_2 IS 'UUID_2 (0x00010000)';


--
-- Name: COLUMN player.gender; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.gender IS 'String64_1 (0x00100000)';


--
-- Name: COLUMN player.name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN player.name IS 'IString64_1 (0x04000000)';


--
-- Name: playerinfo; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE playerinfo (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    creatoracctid character(36),
    creatorid numeric(10,0),
    online integer,
    ki numeric(10,0),
    uuid_1 character(36),
    string64_1 text,
    name text
);


ALTER TABLE public.playerinfo OWNER TO moss;

--
-- Name: TABLE playerinfo; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE playerinfo IS 'Node type 0x17';


--
-- Name: COLUMN playerinfo.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfo.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN playerinfo.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfo.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN playerinfo.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfo.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN playerinfo.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfo.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN playerinfo.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfo.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN playerinfo.online; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfo.online IS 'Int32_1 (0x00000100)';


--
-- Name: COLUMN playerinfo.ki; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfo.ki IS 'UInt32_1 (0x00001000)';


--
-- Name: COLUMN playerinfo.uuid_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfo.uuid_1 IS 'UUID_1 (0x00010000)';


--
-- Name: COLUMN playerinfo.string64_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfo.string64_1 IS 'String64_1 (0x00100000)';


--
-- Name: COLUMN playerinfo.name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfo.name IS 'IString64_1 (0x04000000)';


--
-- Name: playerinfolist; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE playerinfolist (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    creatoracctid character(36),
    creatorid numeric(10,0),
    type integer
);


ALTER TABLE public.playerinfolist OWNER TO moss;

--
-- Name: TABLE playerinfolist; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE playerinfolist IS 'Node type 0x1e';


--
-- Name: COLUMN playerinfolist.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfolist.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN playerinfolist.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfolist.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN playerinfolist.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfolist.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN playerinfolist.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfolist.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN playerinfolist.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfolist.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN playerinfolist.type; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN playerinfolist.type IS 'Int32_1 (0x00000100)';


--
-- Name: score_seq; Type: SEQUENCE; Schema: public; Owner: moss
--

CREATE SEQUENCE score_seq
    INCREMENT BY 1
    MAXVALUE 9999999999
    MINVALUE 100
    CACHE 1;


ALTER TABLE public.score_seq OWNER TO moss;

--
-- Name: SEQUENCE score_seq; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON SEQUENCE score_seq IS 'This sequence is for generating score IDs';


--
-- Name: score_seq; Type: SEQUENCE SET; Schema: public; Owner: moss
--

SELECT pg_catalog.setval('score_seq', 100, true);


--
-- Name: scores; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE scores (
    holder numeric(10,0) NOT NULL,
    name text,
    id numeric(10,0) DEFAULT nextval('score_seq'::regclass) NOT NULL,
    createtime timestamp without time zone DEFAULT now(),
    type integer,
    score numeric(10,0) DEFAULT 0
);


ALTER TABLE public.scores OWNER TO moss;

--
-- Name: TABLE scores; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE scores IS 'generic score tracking';


--
-- Name: COLUMN scores.holder; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN scores.holder IS 'Node ID of whose score this is';


--
-- Name: COLUMN scores.name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN scores.name IS 'Name of score type';


--
-- Name: COLUMN scores.id; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN scores.id IS 'This score''s ID';


--
-- Name: COLUMN scores.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN scores.createtime IS 'Time score was created';


--
-- Name: COLUMN scores.type; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN scores.type IS 'Type of the score';


--
-- Name: COLUMN scores.score; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN scores.score IS 'Score value';


--
-- Name: sdl; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE sdl (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    createageuuid character(36),
    createagename text,
    creatoracctid character(36),
    creatorid numeric(10,0),
    int32_1 numeric(10,0),
    name text,
    blob bytea
);


ALTER TABLE public.sdl OWNER TO moss;

--
-- Name: TABLE sdl; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE sdl IS 'Node type 0x1b';


--
-- Name: COLUMN sdl.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN sdl.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN sdl.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN sdl.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN sdl.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN sdl.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN sdl.createageuuid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN sdl.createageuuid IS 'CreateAgeUUID (0x00000010)';


--
-- Name: COLUMN sdl.createagename; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN sdl.createagename IS 'CreateAgeName (0x00000008)';


--
-- Name: COLUMN sdl.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN sdl.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN sdl.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN sdl.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN sdl.int32_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN sdl.int32_1 IS 'Int32_1 (0x00000100)';


--
-- Name: COLUMN sdl.name; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN sdl.name IS 'String64_1 (0x00100000)';


--
-- Name: COLUMN sdl.blob; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN sdl.blob IS 'Blob_1 (0x40000000)';


--
-- Name: server; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE server (
    nodeid numeric(10,0) NOT NULL
);


ALTER TABLE public.server OWNER TO moss;

--
-- Name: TABLE server; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE server IS '* unused ? *';


--
-- Name: COLUMN server.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN server.nodeid IS 'NodeID (0x00000001)';


--
-- Name: system; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE system (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    creatoracctid character(36),
    creatorid numeric(10,0)
);


ALTER TABLE public.system OWNER TO moss;

--
-- Name: TABLE system; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE system IS 'Node type 0x18';


--
-- Name: COLUMN system.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN system.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN system.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN system.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN system.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN system.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN system.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN system.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN system.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN system.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: textnote; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE textnote (
    nodeid numeric(10,0) NOT NULL,
    createtime timestamp without time zone,
    modifytime timestamp without time zone,
    createageuuid character(36),
    createagename text,
    creatoracctid character(36),
    creatorid numeric(10,0),
    int32_1 numeric(10,0),
    int32_2 numeric(10,0),
    title text,
    value text
);


ALTER TABLE public.textnote OWNER TO moss;

--
-- Name: TABLE textnote; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE textnote IS 'Node type 0x1a';


--
-- Name: COLUMN textnote.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.nodeid IS 'NodeID (0x00000001)';


--
-- Name: COLUMN textnote.createtime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.createtime IS 'CreateTime (0x00000002)';


--
-- Name: COLUMN textnote.modifytime; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.modifytime IS 'ModifyTime (0x00000004)';


--
-- Name: COLUMN textnote.createageuuid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.createageuuid IS 'CreateAgeUUID (0x00000010)';


--
-- Name: COLUMN textnote.createagename; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.createagename IS 'CreateAgeName (0x00000008)';


--
-- Name: COLUMN textnote.creatoracctid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.creatoracctid IS 'CreatorAccctID (0x00000020)';


--
-- Name: COLUMN textnote.creatorid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.creatorid IS 'CreatorID (0x00000040)';


--
-- Name: COLUMN textnote.int32_1; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.int32_1 IS 'Int32_1 (0x00000100)';


--
-- Name: COLUMN textnote.int32_2; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.int32_2 IS 'Int32_2 (0x00000200)';


--
-- Name: COLUMN textnote.title; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.title IS 'String64_1 (0x00100000)';


--
-- Name: COLUMN textnote.value; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN textnote.value IS 'Text_1 (0x10000000)';


--
-- Name: userdefined; Type: TABLE; Schema: public; Owner: moss; Tablespace: 
--

CREATE TABLE userdefined (
    nodeid numeric(10,0) NOT NULL
);


ALTER TABLE public.userdefined OWNER TO moss;

--
-- Name: TABLE userdefined; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON TABLE userdefined IS 'Node type 0x0f? (unused)';


--
-- Name: COLUMN userdefined.nodeid; Type: COMMENT; Schema: public; Owner: moss
--

COMMENT ON COLUMN userdefined.nodeid IS 'NodeID (0x00000001)';


--
-- Name: acctplayerinfo(character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION acctplayerinfo(v_id character, OUT v_ki numeric, OUT v_name text, OUT v_gender text, OUT v_type numeric) RETURNS SETOF record
    AS $$

/* This function fetches a list of players by account id */

DECLARE
v_avatars record;

BEGIN
  for v_avatars in
    select nodeid, name, gender, int32_2 from player where uuid_1 = v_id order by nodeid DESC loop
      v_ki := v_avatars.nodeid;
      v_name := v_avatars.name;
      v_gender := v_avatars.gender;
      v_type := v_avatars.int32_2;
      return next;
    end loop;
  return;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.acctplayerinfo(v_id character, OUT v_ki numeric, OUT v_name text, OUT v_gender text, OUT v_type numeric) OWNER TO moss;

--
-- Name: addmarker(numeric, double precision, double precision, double precision, character, character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION addmarker(v_gameid numeric, v_x double precision, v_y double precision, v_z double precision, v_name character, v_age character) RETURNS integer
    AS $$

DECLARE
numrows integer;
markerid numeric;
nextid numeric;

BEGIN
  select count(*) into numrows from markertemplates where game_id = v_gameid;
  if numrows != 1 then
    return -1;
  end if;
  select next_number into markerid from markertemplates where game_id = v_gameid;
  insert into markers values(v_gameid, v_x, v_y, v_z, markerid, v_name, v_age);
  nextid := markerid + 1;
  update markertemplates set next_number = nextid where game_id = v_gameid;
  return markerid;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.addmarker(v_gameid numeric, v_x double precision, v_y double precision, v_z double precision, v_name character, v_age character) OWNER TO moss;

--
-- Name: addnode(numeric, numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION addnode(v_parent numeric, v_child numeric, v_owner numeric) RETURNS integer
    AS $$
/*
   This function adds a row to the noderefs table.  It checks for duplicate noderefs, and also
   makes sure that parent, child, and owner nodes exist in the master node table.  If the owner
   node is zero, record insert is permitted because zero is the owner for system created nodes.
*/

DECLARE
  numrows integer;
  v_nodeid numeric;
  v_ptype numeric;
  v_notifier numeric;

begin
  /* init variables */
  numrows := 0;

  /* XXX - We should add code here to make sure one cannot add nodes to bad places.  For example,
           no text notes in age owners lists, and such things.  This will also prevent the exploit
           of adding nodes to our inbox, so we can access nodes that Plasma normally would not allow
           us to
  */

  /* Check to see if this parent -> child pair already exists. */
  select count(*) into numrows from noderefs where parent=v_parent and child=v_child;
  if numrows > 0 then
    return 1; /* noderef exists */
  end if;
  
  /* Check to see if the parent, child, and owner nodes exist in master node table */
  select nodeid,type from nodes where nodeid = v_parent into v_nodeid,v_ptype;
  if not FOUND then
    return 2; /* node not found */
  end if;

  select nodeid from nodes where nodeid = v_child into v_nodeid;
  if not FOUND then
    return 2; /* node not found */
  end if;

  select nodeid from nodes where nodeid = v_owner into v_nodeid;
  if ((not FOUND) and (v_owner != 0)) then
    return 2; /* node not found */
  end if;

  /* Hmm..... a given node can be in the tree in more than one place, that
     is to say it can have more than one parent.
     To my knowledge the situations are:
     - leaf nodes can have multiple parents, but said parents (folders and
       *infolists) themselves have only one parent
     - multiple AgeLinks; each age owner, visitor, etc. has a separately
       parented link, but the top of the notifier tree is the AgeInfo *below*
       the AgeLink
  */
  if v_ptype in (2, 24, 3, 33) then
    /* player, system, age, ageinfo: notifier is self (top of tree) */
    v_notifier := v_parent;
  else
    select notifier from noderefs where child=v_parent limit 1 into v_notifier;
    if not FOUND then
      v_notifier := 0;
    end if;
  end if;
  insert into noderefs values (v_parent, v_child, v_owner, v_notifier);
  return 0;

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.addnode(v_parent numeric, v_child numeric, v_owner numeric) OWNER TO moss;

--
-- Name: addtoscore(numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION addtoscore(v_id numeric, v_value numeric) RETURNS integer
    AS $$

/* 
   This function adds a value (which may be negative) to the score. If
   the score type does not allow adding negative points, or adding points
   at all, no change is made and an error is returned.

   0 = success
   1 = negative addition not allowed, or score is fixed
   2 = score not found
*/

DECLARE
  numrows integer;
  scoretype integer;
  scoreval numeric;

BEGIN
  /* Check that this score exists. */
  select count(*) into numrows from scores where id=v_id;
  if numrows = 0 then
    return 2; /* score does not exist */
  end if;

  /* Check score type. */
  select type, score into scoretype, scoreval from scores where id=v_id;
  if v_value < 0 then
    if scoretype != 2 then /* 2 == kAccumAllowNegative */
      return 1;
    end if;
  end if;
  if scoretype = 0 then /* 0 == kFixed */
    return 1;
  end if;

  /* Do the change. */
  scoreval := scoreval + v_value;
  update scores set score=scoreval where id=v_id;
  return 0;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.addtoscore(v_id numeric, v_value numeric) OWNER TO moss;

--
-- Name: capturedmarkers(numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION capturedmarkers(v_gameid numeric, v_player numeric, OUT v_id numeric, OUT v_value numeric) RETURNS SETOF record
    AS $$

DECLARE
marker record;

BEGIN
  for marker in
    select marker_number, value from markersinplay where game_id = v_gameid and player = v_player and value != 0 order by marker_number loop
      v_id := marker.marker_number;
      v_value := marker.value;
      return next;
    end loop;
  return;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.capturedmarkers(v_gameid numeric, v_player numeric, OUT v_id numeric, OUT v_value numeric) OWNER TO moss;

--
-- Name: clearvault(); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION clearvault() RETURNS void
    AS $$
/*
   This function cleans out the entire vault, so you can start over if you want.
*/

begin

  /* delete master node entries, which also delets all subtables */
  delete from nodes;

  /* delete all noderefs */
  delete from noderefs;

  /* delete markertemplates */
  delete from markertemplates;

  /* delete scores */
  delete from scores;

  /* delete connected (should be empty, but making sure) */
  delete from connected;

  /* delete admin */
  delete from admin;

  /* reset sequences min and start values to 100 */
  ALTER SEQUENCE nodeid_seq MINVALUE 100;
  PERFORM setval('public.nodeid_seq', 100, true);

  ALTER SEQUENCE score_seq MINVALUE 100;
  PERFORM setval('public.score_seq', 100, true);

  ALTER SEQUENCE markertemplate_seq MINVALUE 100;
  PERFORM setval('public.markertemplate_seq', 100, true);

  return;

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.clearvault() OWNER TO moss;

--
-- Name: createage(text, text, text, text, character, character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION createage(v_filename text, v_instancename text, v_username text, v_displayname text, v_ageuuid character, v_parentuuid character, OUT v_agenode numeric, OUT v_ageinfonode numeric) RETURNS record
    AS $$

/*  This function creates an age.  Awesome, eh! */

DECLARE
  v_sysnode numeric;
  v_nodeholder numeric;  /* for adding noderefs */
  v_length integer;  /* for age owner link add */
  v_playername text; /* for age owner link add */
  v_playerinfonode numeric; /* for age owner link add */
  v_uuidcount integer;
  c_null_uuid constant character(36) := '00000000-0000-0000-0000-000000000000';  /* using c_ to signify constants */
  v_sequence numeric; /* used to generate a new sequence number */

  v_createageuuid character (36); /* using this because we cannot modify an IN parameter's value */
  v_ageparent character(36); /* using this because we cannot modify an IN parameter's value */
  

BEGIN
    select nodeid from system limit 1 into v_sysnode;
    if v_sysnode is NULL then /* we have to have a system node */
      v_agenode := 1;  /* set both return values to ERROR_INTERNAL */
      v_ageinfonode := 1;
      return;
    end if;

    if v_ageuuid = c_null_uuid and v_parentuuid != c_null_uuid then  /* this is a child age */
      v_createageuuid := uuid(); /* generate a uuid for this child age */
      v_ageparent := v_parentuuid;
    else
      v_createageuuid := v_ageuuid;
      v_ageparent := NULL;
    end if;

    if v_ageparent != c_null_uuid then
      /* check for a pre-existing child age with this parent uuid and filename */
      select count(uuid_1) from age where uuid_2 = v_ageparent and filename = v_filename into v_uuidcount;
      if v_uuidcount > 0 then /* age found */
        select nodeid from age where uuid_2 = v_ageparent and filename = v_filename into v_agenode;
        select nodeid from ageinfo where uuid_2 = v_ageparent and string64_2 = v_filename into v_ageinfonode;
        return;
      end if;
    else
      /* not a child age - check for existing age */
      select count(uuid_1) from age where uuid_1 = v_createageuuid into v_uuidcount;
      if v_uuidcount > 0 then  /* this uuid already exists - return existing nodes */
        select nodeid from age where uuid_1 = v_createageuuid into v_agenode;
        select nodeid from ageinfo where uuid_1 = v_createageuuid into v_ageinfonode;
        return;
      end if;
    end if;
   
   
    /* create the age node */
    select nextval('public.nodeid_seq') into v_agenode;
    insert into nodes (nodeid, type) values (v_agenode, 3);
    insert into age values (v_agenode, now(), now(), v_createageuuid, v_agenode,  v_createageuuid, v_ageparent, v_filename);

    /* get the system node and link it to the age node */
     PERFORM addnode(v_agenode, v_sysnode, 0);

    /* create and link AgeDevices Folder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 22);
    insert into folder values (v_nodeholder, now(), now(), NULL, NULL, v_createageuuid, v_agenode, 15, NULL);
    PERFORM addnode(v_agenode, v_nodeholder, 0); /* server owns all the noderefs in this function */

    /* create and link chronicle folder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 22);
    insert into folder values (v_nodeholder, now(), now(), NULL, NULL, v_createageuuid, v_agenode, 6, NULL);
    PERFORM addnode(v_agenode, v_nodeholder, 0);


    /* create and link SubAges folder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 34);
    insert into ageinfolist values (v_nodeholder, now(), now(), v_createageuuid, v_agenode, 9);
    PERFORM addnode(v_agenode, v_nodeholder, 0);

    /* create and link PeopleIKnowAboutFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 30);
    insert into playerinfolist values (v_nodeholder, now(), now(), v_createageuuid, v_agenode, 4);
    PERFORM addnode(v_agenode, v_nodeholder, 0);   


    /* create and link AgeInfo node */
    select nextval('public.nodeid_seq') into v_ageinfonode;
    insert into nodes (nodeid, type) values (v_ageinfonode, 33);

    if (v_filename = 'Neighborhood' and v_username = 'DRC') then
      /* We are creating a DRC Bevin.  Give it a sequence number and set int32_2 to '1' (public) */
      select int32_1 from ageinfo where string64_2 = 'Neighborhood' and string64_3 = 'Bevin' and
        string64_4 = 'DRC' order by int32_1 DESC limit 1 into v_sequence;
      if v_sequence is null then
        v_sequence := 1;
      else
        v_sequence := v_sequence + 1;
      end if;
      insert into ageinfo values (v_ageinfonode, now(), now(), v_createageuuid, v_agenode, v_sequence, 1, -1, v_agenode, 0, 0, v_createageuuid, 
         v_ageparent,  v_filename, v_instancename, v_username, v_displayname);
      PERFORM addnode(v_agenode, v_ageinfonode, 0);

    elseif v_filename = 'city' and v_instancename = 'Ae''gura' and v_username is NULL then
      /* We are creating a global city. */
      insert into ageinfo values (v_ageinfonode, now(), now(), v_createageuuid, v_agenode, 0, 1, -1, v_agenode, 0, 0, v_createageuuid, 
         v_ageparent, v_filename, v_instancename, v_username, v_displayname);
      PERFORM addnode(v_agenode, v_ageinfonode, 0);

    elseif v_filename = 'Neighborhood02' and v_instancename = 'Kirel' and v_username is NULL then
      /* We are creating public Kirel */
      insert into ageinfo values (v_ageinfonode, now(), now(), v_createageuuid, v_agenode, 0, 1, -1, v_agenode, 0, 0, v_createageuuid, 
         v_ageparent, v_filename, v_instancename, v_username, v_displayname);
      PERFORM addnode(v_agenode, v_ageinfonode, 0);

    elseif v_filename = 'GreatTreePub' and v_instancename = 'The Watcher''s Pub' and v_username is NULL then
      /* We are creating public Watcher's Pub */
      insert into ageinfo values (v_ageinfonode, now(), now(), v_createageuuid, v_agenode, 0, 1, -1, v_agenode, 0, 0, v_createageuuid, 
         v_ageparent, v_filename, v_instancename, v_username, v_displayname);
      PERFORM addnode(v_agenode, v_ageinfonode, 0);

    elseif v_filename = 'BahroCave' and v_instancename = 'BahroCave' and v_username = 'BahroCave' and v_displayname = 'BahroCave' then
      /* We are creating a BahroCave.  Give it a sequence number */
      select int32_1 from ageinfo where string64_2 = 'BahroCave' and string64_4 = 'BahroCave' and text_1 = 'BahroCave'
        order by int32_1 DESC limit 1 into v_sequence;
      if v_sequence is null then
        v_sequence := 1;
      else
        v_sequence := v_sequence + 1;
      end if;
      insert into ageinfo values (v_ageinfonode, now(), now(), v_createageuuid, v_agenode, v_sequence, NULL, -1, v_agenode, 0, 0,
         v_createageuuid, v_ageparent, v_filename, v_instancename, v_username, v_displayname);
      PERFORM addnode(v_agenode, v_ageinfonode, 0);

    elseif v_filename = 'LiveBahroCaves' and v_instancename = 'LiveBahroCaves' and v_username = 'LiveBahroCaves' and v_displayname = 'LiveBahroCaves' then
      /* We are creating a LiveBahroCave.  Give it a sequence number */
      select int32_1 from ageinfo where string64_2 = 'LiveBahroCaves' and string64_4 = 'LiveBahroCaves' and text_1 = 'LiveBahroCaves'
        order by int32_1 DESC limit 1 into v_sequence;
      if v_sequence is null then
        v_sequence := 1;
      else
        v_sequence := v_sequence + 1;
      end if;
      insert into ageinfo values (v_ageinfonode, now(), now(), v_createageuuid, v_agenode, v_sequence, NULL, -1, v_agenode, 0, 0,
         v_createageuuid, v_ageparent, v_filename, v_instancename, v_username, v_displayname);
      PERFORM addnode(v_agenode, v_ageinfonode, 0);

    elseif v_filename = 'Neighborhood' and v_username != 'DRC' then
      /* We are creating an avatar's personal hood.  Set int32_2 to '1' (public)  */
      insert into ageinfo values (v_ageinfonode, now(), now(), v_createageuuid, v_agenode, 0, 1, -1, v_agenode, 0, 0, v_createageuuid, 
         v_ageparent,  v_filename, v_instancename, v_username, v_displayname);
      PERFORM addnode(v_agenode, v_ageinfonode, 0);

    else
      /* default age create */
      insert into ageinfo values (v_ageinfonode, now(), now(), v_createageuuid, v_agenode, 0, NULL, -1, v_agenode, 0, 0, v_createageuuid, 
         v_ageparent,  v_filename, v_instancename, v_username, v_displayname);
      PERFORM addnode(v_agenode, v_ageinfonode, 0);
    end if; 

    /* create nodes which are children of the AgeInfo node */

    /* create and link CanVisitFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 30);
    insert into playerinfolist values (v_nodeholder, now(), now(), v_createageuuid, v_agenode, 18);
    PERFORM addnode(v_ageinfonode, v_nodeholder, 0);

    /* create and link empty SDL node */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 27);
    insert into sdl values (v_nodeholder, now(), now(), v_createageuuid, v_filename, v_createageuuid, v_agenode, 0, v_filename, NULL );
    PERFORM addnode(v_ageinfonode, v_nodeholder, 0);   

    /* create and link AgeOwnersFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 30);
    insert into playerinfolist values (v_nodeholder, now(), now(), v_createageuuid, v_agenode, 19);
    PERFORM addnode(v_ageinfonode, v_nodeholder, 0);

    /* create and link ChildAgesFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 34);
    insert into ageinfolist values (v_nodeholder, now(), now(), v_createageuuid, v_agenode, 31);
    PERFORM addnode(v_ageinfonode, v_nodeholder, 0);

    /* If creating a global city, add and link GameScoresFolder */
    if v_filename = 'city' and v_instancename = 'Ae''gura' and v_username is NULL then
      select nextval('public.nodeid_seq') into v_nodeholder;
      insert into nodes (nodeid, type) values (v_nodeholder, 22);
      insert into folder values (v_nodeholder, now(), now(), NULL, NULL, v_createageuuid, v_agenode, 32, NULL);
      PERFORM addnode(v_ageinfonode, v_nodeholder, 0);
    end if;

RETURN;

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.createage(v_filename text, v_instancename text, v_username text, v_displayname text, v_ageuuid character, v_parentuuid character, OUT v_agenode numeric, OUT v_ageinfonode numeric) OWNER TO moss;

--
-- Name: createmarkergame(numeric, numeric, character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION createmarkergame(v_owner numeric, v_type numeric, v_name character, OUT v_gameid numeric, OUT v_uuid character) RETURNS record
    AS $$

BEGIN
  v_uuid := uuid();
  insert into markertemplates(uuid, owner, type, name) values(v_uuid, v_owner, v_type, v_name);
  select game_id into v_gameid from markertemplates where uuid = v_uuid;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.createmarkergame(v_owner numeric, v_type numeric, v_name character, OUT v_gameid numeric, OUT v_uuid character) OWNER TO moss;

--
-- Name: createplayer(text, text, character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION createplayer(v_reqname text, v_reqgender text, v_id character, OUT v_ki numeric, OUT v_type numeric, OUT v_name text, OUT v_gender text, OUT v_neighbors numeric, OUT v_playerinfonode numeric) RETURNS record
    AS $$

/*  This function creates a player.  Awesome, eh! */

DECLARE
  v_sysnode numeric;
  v_allplayersfolder numeric;
  v_link numeric; /* for creating the three default age link nodes */
  v_linkageinfonode numeric; /* for creating the AgeInfo nodes under the age link nodes */
  v_agesiown numeric; /* The created AgesIOwnFolder node */
  v_linkagenode numeric; /* used for the special case link under Personal age */
  v_hoodownercount integer; /* number of hood owners */
  v_ageownernode numeric; /* age owners folder */
  v_nodeholder numeric; /* used for noderefs */
  v_cityageowners numeric; /* AgesOwners for the city */
  v_playercount integer;  /* used to count the number of players this account has */

  c_admin_uuid character(36);
  c_null_uuid constant character(36) := '00000000-0000-0000-0000-000000000000';  /* using c_ to signify constants */
  

BEGIN
    select nodeid from system limit 1 into v_sysnode;
    if v_sysnode is NULL then /* we have to have a system node */
      v_ki := 1; /* set KI number to ERROR_INTERNAL */
      return;
    end if;

    select count(nodeid) from player where creatoracctid = v_id into v_playercount;
    if v_playercount > 4 then /* error - too many players */
      v_ki := 19;  /* set KI to ERROR_MAX_PLAYERS */
      return;
    end if;

    select count(name) from player where lower(name) = lower(v_reqname) into v_playercount;
    if v_playercount > 0 then /* error - player name already used */
      v_ki := 12; /* set KI number to ERROR_PLAYER_EXISTS */
      return;
    end if;

  /* check to see if this is a visitor account */
   if (select visitor from accounts where id = v_id) = FALSE or (select visitor from accounts where id = v_id) is NULL then
     v_type := 1; /* explorer */
   else
     v_type := 0;  /* visitor */
   end if;

    /* Here can be done validation of names and gender, if needed */

    v_name := v_reqname;
    v_gender := v_reqgender;

    if v_id is NULL then /* error somehow - bail out */
      v_ki := 0;
      v_type := 0;
      v_name := '';
      v_gender := '';
      return;
    end if;
    


    /* create and link player node */
    select nextval('public.nodeid_seq') into v_ki;
    insert into nodes (nodeid, type) values (v_ki, 2);
    /* For player nodes, it appears creatorid == 0 (unlike for ages), 
       perhaps because the player does not yet exist
    */
    insert into player values (v_ki, now(), now(), v_id, 0, 0, v_type, 0, v_id, NULL, v_gender, v_name);
    PERFORM addnode(v_ki, v_sysnode, 0);

   /* create and link PlayerInfoNode */
    select nextval('public.nodeid_seq') into v_playerinfonode;
    insert into nodes (nodeid, type) values (v_playerinfonode, 23);
    insert into playerinfo values (v_playerinfonode, now(), now(), v_id, v_ki, NULL, v_ki, NULL, NULL, v_name);
    PERFORM addnode(v_ki, v_playerinfonode, v_ki);

   /* link playerinfo to AllPlayers folder (Alcugs) */
   select nodeid from playerinfolist where type = 12 into v_allplayersfolder;
   if FOUND then
     PERFORM addnode(v_allplayersfolder, v_playerinfonode, 0);
   end if;

    /* create and link BuddyListFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 30);
    insert into playerinfolist values (v_nodeholder, now(), now(), v_id, v_ki, 2);
    PERFORM addnode(v_ki, v_nodeholder, v_ki);      

    /* create and link AgeJournalsFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 22);
    insert into folder values (v_nodeholder, now(), now(), NULL, NULL, v_id, v_ki, 14, NULL);
    PERFORM addnode(v_ki, v_nodeholder, v_ki);

    /* create and link AvatarClosetFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 22);
    insert into folder values (v_nodeholder, now(), now(), NULL, NULL, v_id, v_ki, 25, NULL);
    PERFORM addnode(v_ki, v_nodeholder, v_ki);

    /* create and link ChronicleFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 22);
    insert into folder values (v_nodeholder, now(), now(), NULL, NULL, v_id, v_ki, 6, NULL);
    PERFORM addnode(v_ki, v_nodeholder, v_ki);

   /* create and link AgesIOwnFolder */
    select nextval('public.nodeid_seq') into v_agesiown;
    insert into nodes (nodeid, type) values (v_agesiown, 34);
    insert into ageinfolist values (v_agesiown, now(), now(), v_id, v_ki, 23);
    PERFORM addnode(v_ki, v_agesiown, v_ki);

    /* create an AgeLinkNode for the hood and link to AgesIOwnFolder */
    select nextval('public.nodeid_seq') into v_link;
    insert into nodes (nodeid, type) values (v_link, 28);
    insert into agelink values (v_link, now(), now(), NULL, NULL, v_id, v_ki, 0, NULL, E'\\034\\000\\000\\000Default:LinkInPointDefault:;');
    PERFORM addnode(v_agesiown, v_link, v_ki);

    /* get the highest sequence DRC hood */
    select nodeid from ageinfo where string64_2 = 'Neighborhood' and string64_3 = 'Bevin' and string64_4 = 'DRC'
      order by int32_1 DESC limit 1 into v_linkageinfonode;
  
    /* get the number of age owners for the above hood */
    select count(child) from noderefs where parent = (
    SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where 
      noderefs.parent = v_linkageinfonode and playerinfolist.type = 19 limit 1) into v_hoodownercount;

    if v_hoodownercount > 20 or v_linkageinfonode is NULL then
      /* 20+ owners - create new DRC Bevin */
      select v_ageinfonode from createage('Neighborhood', 'Bevin', 'DRC', '', uuid(), NULL) into v_linkageinfonode;
      PERFORM addnode(v_link, v_linkageinfonode, v_ki); /* link it to our age link node */
      /* get the age owners node */
      SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where 
        noderefs.parent = v_linkageinfonode and playerinfolist.type = 19 limit 1 into v_neighbors;
      /* make our player node an owner of this hood */
      PERFORM addnode(v_neighbors, v_playerinfonode, v_ki);
    else
      /* less then 20 hood owners - we can use the existing one */
      PERFORM addnode(v_link, v_linkageinfonode, v_ki);
      /* age owners node */
      SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where 
        noderefs.parent = v_linkageinfonode and playerinfolist.type = 19 limit 1 into v_neighbors;
      /* make our player node an owner of this hood */
      PERFORM addnode(v_neighbors, v_playerinfonode, v_ki);
    end if;

    /* create an agelink for Personal age and link to AgesIOwnFolder */
    select nextval('public.nodeid_seq') into v_link;
    insert into nodes (nodeid, type) values (v_link, 28);
    insert into agelink values (v_link, now(), now(), NULL, NULL, v_id, v_ki, 0, NULL, E'\\034\\000\\000\\000Default:LinkInPointDefault:;');
    PERFORM addnode(v_agesiown, v_link, v_ki);

    /* create the Personal age */
    select v_agenode, v_ageinfonode from createage('Personal', 'Relto', v_name || '''s', v_name || '''s Relto', uuid(), NULL) into
       v_linkagenode, v_linkageinfonode;
    /* add it to the agelink */
    PERFORM addnode(v_link, v_linkageinfonode, v_ki);
    /* age owners node */
    SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where 
      noderefs.parent = v_linkageinfonode and playerinfolist.type = 19 limit 1 into v_ageownernode;
    /* make our player node an owner of this Personal age */
    PERFORM addnode(v_ageownernode, v_playerinfonode, v_ki);
    /* special case for Personal age - make AgesIOwn of player node a child of this age node */
    PERFORM addnode(v_linkagenode, v_agesiown, v_ki);

    /* create an agelink for global city and link to AgesIOwnFolder */
    select nextval('public.nodeid_seq') into v_link;
    insert into nodes (nodeid, type) values (v_link, 28);
    /* client will fill in this agelink */
    insert into agelink values (v_link, now(), now(), NULL, NULL, v_id, v_ki, 0, NULL, NULL);
    PERFORM addnode(v_agesiown, v_link, v_ki);

    /* get the ageinfo node for the global city and add to the link */
    PERFORM addnode(v_link, (select nodeid from ageinfo where string64_2 = 'city' and string64_3 = 'Ae''gura' and
      int32_2 = 1 and string64_4 is NULL limit 1), v_ki);

 
    /* create and link AgesICanVisitFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 34);
    insert into ageinfolist values (v_nodeholder, now(), now(), v_id, v_ki, 24);
    PERFORM addnode(v_ki, v_nodeholder, v_ki);

    /* create and link IgnoreListFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 30);
    insert into playerinfolist values (v_nodeholder, now(), now(), v_id, v_ki, 3);
    PERFORM addnode(v_ki, v_nodeholder, v_ki);      
    
    /* create and link InboxFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 22);
    insert into folder values (v_nodeholder, now(), now(), NULL, NULL, v_id, v_ki, 1, NULL);
    PERFORM addnode(v_ki, v_nodeholder, v_ki);

    /* create and link PlayerInviteFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 22);
    insert into folder values (v_nodeholder, now(), now(), NULL, NULL, v_id, v_ki, 28, NULL);
    PERFORM addnode(v_ki, v_nodeholder, v_ki);   

    /* create and link PeopleIKnowAboutFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 30);
    insert into playerinfolist values (v_nodeholder, now(), now(), v_id, v_ki, 4);
    PERFORM addnode(v_ki, v_nodeholder, v_ki); 
   
    /* create and link AvatarOutfitFolder */
    select nextval('public.nodeid_seq') into v_nodeholder;
    insert into nodes (nodeid, type) values (v_nodeholder, 22);
    insert into folder values (v_nodeholder, now(), now(), NULL, NULL, v_id, v_ki, 7, NULL);
    PERFORM addnode(v_ki, v_nodeholder, v_ki); 

  /* perhaps we are done */


RETURN;

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.createplayer(v_reqname text, v_reqgender text, v_id character, OUT v_ki numeric, OUT v_type numeric, OUT v_name text, OUT v_gender text, OUT v_neighbors numeric, OUT v_playerinfonode numeric) OWNER TO moss;

--
-- Name: deleteage(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION deleteage(v_ageinfonode numeric) RETURNS void
    AS $$
/*
  This is an initial attempt at age delete.
*/
declare
  v_nodeid numeric;
  v_invitedplayer numeric;
  v_agelink numeric;
  v_childageinfo numeric;
  v_childnodes numeric;
  v_noderefs noderefs;
  v_agedevicestext numeric;
  v_agedevicesfolder numeric;
  v_devicecontents numeric;
  v_agenode numeric;
  
begin
  if (select count(nodeid) from ageinfo where nodeid = v_ageinfonode) = 0 then
    /* This is not an ageinfo node, or the node does not exist.  Either
       way, bail out.
    */
    return;
  end if;

  /* Check for global city, Kveer, and Kirel.  For these, string64_4 is NULL.
     This is a good check because Uru protocol has no way to send a NULL.
     It can only send an empty string.  If we get passed one of these, bail
     out.
  */
  if (select string64_4 from ageinfo where nodeid = v_ageinfonode) is NULL then
    -- RAISE NOTICE 'deleteage(): Global city, Kveer, or Kirel passed in.  Exiting.';
    return; 
  end if;

  /* check for the static UUID ages and do not delete those either */
  if (select uuid_1 from ageinfo where nodeid = v_ageinfonode) in 
    ('35624301-841e-4a07-8db6-b735cf8f1f53',
     '381fb1ba-20a0-45fd-9bcb-fd5922439d05',
     'e8306311-56d3-4954-a32d-3da01712e9b5',
     '9420324e-11f8-41f9-b30b-c896171a8712',
     '5cf4f457-d546-47dc-80eb-a07cdfefa95d',
     '68e219e0-ee25-4df0-b855-0435584e29e2',
    'e8a2aaed-5cab-40b6-97f3-6d19dd92a71f') then
    -- RAISE NOTICE 'deleteage(): Static UUID age passed in.  Exiting.';
    return;
  end if;

  /* get AgeOwnersFolder node and check for owners */
  SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where 
    noderefs.parent = v_ageinfonode and playerinfolist.type = 19 limit 1 into v_nodeid;
  if (select count(child) from noderefs where parent = v_nodeid) > 0 then
    /* we still have owners - we cannot delete this age */
    -- RAISE NOTICE 'deleteage(): We have owners other than ourselves.  Exiting.';
    return;
  else
    /* unlink any other nodes under AgeOwnersFolder */
    delete from noderefs where parent = v_nodeid;
    /* unlink the node and delete it */
    PERFORM removenode(v_ageinfonode, v_nodeid);
  end if;

  /* get CanVisitFolder node and check for visitors */
  SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where 
    noderefs.parent = v_ageinfonode and playerinfolist.type = 18 limit 1 into v_nodeid;
  if (select count(child) from noderefs where parent = v_nodeid) > 0 then
    /* we still have visitors - we cannot delete this age (MOUL does it this way) */
    /* if we change this to delete ages with visitors, we then have to find
       a way to propagate the ref remove to other clients, so the MOUL way is
       certainly simpler */
    -- RAISE NOTICE 'deleteage(): We have age visitors.  Exiting.';
    return;
  else  
    /* unlink any other nodes under CanVisit */
    delete from noderefs where parent = v_nodeid;
    /* unlink and delete CanVisit folder */
    PERFORM removenode(v_ageinfonode, v_nodeid);
  end if;

  /* Check if this is a hood and, if so, delete PelletScores for it */
  if (select string64_2 from ageinfo where nodeid = v_ageinfonode) = 'Neighborhood' then
    delete from scores where holder = v_ageinfonode;
  end if;

/* get ChildAges folder */
  SELECT nodeid FROM ageinfolist INNER JOIN noderefs ON ageinfolist.nodeid = noderefs.child where 
    noderefs.parent = v_ageinfonode and ageinfolist.type = 31 limit 1 into v_nodeid;
  /* get the agelinks and delete the child ages */
  for v_agelink in select nodeid from agelink inner join noderefs on agelink.nodeid = noderefs.child where
    noderefs.parent = v_nodeid
  loop
    SELECT nodeid FROM ageinfo INNER JOIN noderefs ON ageinfo.nodeid = noderefs.child
          where noderefs.parent = v_agelink limit 1 into v_childageinfo;
    /* remove agelink -> ageinfo link */
    delete from noderefs where parent=v_agelink and child=v_childageinfo;
    /* delete the child age */
    PERFORM deleteage(v_childageinfo);
    /* unlink and delete agelink */
    PERFORM removenode(v_nodeid, v_agelink);
  end loop;
  /* unlink any other nodes under ChildAges */
  delete from noderefs where parent = v_nodeid;
  /* unlink and delete the ChildAges node */
  PERFORM removenode(v_ageinfonode, v_nodeid);

  /* see if we have any AgeData */
  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
    noderefs.parent = v_ageinfonode and folder.name ='AgeData' limit 1 into v_nodeid;
  if v_nodeid is not NULL then
    for v_childnodes in select child from noderefs where parent = v_nodeid -- Get child nodes of AgeData
    loop
      PERFORM removenode(v_nodeid, v_childnodes);  -- remove them
    end loop;
    PERFORM removenode(v_ageinfonode, v_nodeid);  -- remove AgeData node
  end if;

  /* unlink and delete the SDL node */
  SELECT nodeid FROM sdl INNER JOIN noderefs ON sdl.nodeid = noderefs.child where 
    noderefs.parent = v_ageinfonode limit 1 into v_nodeid;
  PERFORM removenode(v_ageinfonode, v_nodeid);

  /* get age node, because ageinfo node and noderef will soon be gone */
  SELECT nodeid FROM age INNER JOIN noderefs ON age.nodeid = noderefs.parent where 
    noderefs.child = v_ageinfonode limit 1 into v_agenode;

  /* Age -->  AgesIOwn for Personal - unlink only */
  if (select count(String64_2) from ageinfo where String64_2 = 'Personal') = 1 then
    SELECT nodeid FROM ageinfolist INNER JOIN noderefs ON ageinfolist.nodeid = noderefs.child where 
      noderefs.parent = v_agenode and ageinfolist.type = 23 limit 1 into v_nodeid;
    delete from noderefs where parent = v_ageinfonode and child = v_nodeid;
  end if;


  /*  unlink any other nodes under AgeInfo  */
  delete from noderefs where parent = v_ageinfonode;
  /* unlink and delete the ageinfo node */
  PERFORM removenode(v_agenode, v_ageinfonode);

   /* get SubAges folder */
  SELECT nodeid FROM ageinfolist INNER JOIN noderefs ON ageinfolist.nodeid = noderefs.child where 
    noderefs.parent = v_agenode and ageinfolist.type = 9 limit 1 into v_nodeid;
  /* get the agelinks and delete the sub ages */
  for v_agelink in select nodeid from agelink inner join noderefs on agelink.nodeid = noderefs.child where
    noderefs.parent = v_nodeid
  loop
    SELECT nodeid FROM ageinfo INNER JOIN noderefs ON ageinfo.nodeid = noderefs.child
          where noderefs.parent = v_agelink limit 1 into v_childageinfo;
    /* delete the agelink -> ageinfo link */
    delete from noderefs where parent=v_agelink and child = v_childageinfo;
    /* delete the sub age */
    PERFORM deleteage(v_childageinfo);
    /* unlink and delete agelink */
    PERFORM removenode(v_nodeid, v_agelink);
  end loop;
  /* unlink any other nodes under SubAges */
  delete from noderefs where parent = v_nodeid;
  /* unlink and delete SubAge node */
  PERFORM removenode(v_agenode, v_nodeid);


  /* PeopleIKnowAbout folder */
  SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where 
    noderefs.parent = v_agenode and playerinfolist.type = 4 limit 1 into v_nodeid;
  /* child nodes */
  for v_noderefs in select * from fetchnoderefs(v_nodeid)
  loop
    delete from noderefs where parent = v_nodeid and child = v_noderefs.child;
   /* no deleting nodes here!  These are PlayerInfo nodes.  Deleting them would be.... unfortunate. */
  end loop;
  /* unlink and delete the PIKA node */
  PERFORM removenode(v_agenode, v_nodeid);

  /* Chronicle node */
  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
    noderefs.parent = v_agenode and folder.type = 6 limit 1 into v_nodeid;
  /* child nodes */
  for v_noderefs in select * from fetchnoderefs(v_nodeid) order by parent desc
  loop
    PERFORM removenode(v_noderefs.parent, v_noderefs.child);
  end loop;
  /* unlink and delete the Chronicle node */
  PERFORM removenode(v_agenode, v_nodeid);

  /* age devices */
  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
    noderefs.parent = v_agenode and folder.type = 15 limit 1 into v_nodeid;
  /* child nodes */
  for v_noderefs in select * from fetchnoderefs(v_nodeid) order by parent desc
  loop
    PERFORM removenode(v_noderefs.parent, v_noderefs.child);
  end loop;
  /* unlink and delete the age devices node */
  PERFORM removenode(v_agenode, v_nodeid);


  /* age devices */
--  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
--    noderefs.parent = v_agenode and folder.type = 15 limit 1 into v_nodeid;
  /* get the device nodes */
--  for v_agedevicestext in select child from noderefs where parent = v_nodeid
--  loop
--    for v_agedevicesfolder in select child from noderefs where parent = v_agedevicestext
--    loop
--      for v_devicecontents in select child from noderefs where parent = v_agedevicesfolder
--      loop
--        PERFORM removenode(v_agedevicesfolder, v_devicecontents);
--     end loop;
--    PERFORM removenode(v_agedevicestext, v_agedevicesfolder);
--   end loop;
--  PERFORM removenode(v_nodeid, v_agedevicestext);
--  end loop;
  /* unlink any other nodes under AgeDevices  */
--  delete from noderefs where parent = v_nodeid;
  /* unlink and remove the AgeDevices node */
--  PERFORM removenode(v_agenode, v_nodeid);

  /* unlink anything else which may be under the age node */
  delete from noderefs where parent = v_agenode;
  /* unlink this age node and delete it */
  delete from noderefs where parent = v_agenode; /* should not be anything left under here */
  delete from noderefs where child= v_agenode; /* remove refs to this age from all parents */
  delete from nodes where nodeid = v_agenode;  /* bye bye, age */

  return;

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.deleteage(v_ageinfonode numeric) OWNER TO moss;

--
-- Name: deletemarker(numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION deletemarker(v_gameid numeric, v_id numeric) RETURNS integer
    AS $$

/* returns 1 if the marker did not exist, 0 otherwise */

DECLARE
numrows integer;

BEGIN
  select count(*) into numrows from markers where game_id = v_gameid and marker_number = v_id;
  if numrows = 0 then
    return 1;
  end if;
  delete from markers where game_id = v_gameid and marker_number = v_id;
  /* should also delete from markersinplay */
  return 0;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.deletemarker(v_gameid numeric, v_id numeric) OWNER TO moss;

--
-- Name: deletemarkergame(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION deletemarkergame(v_gameid numeric) RETURNS integer
    AS $$
/* 
   0 = success
   1 = deletion not allowed because a node refers to the game
   2 = game not found
*/

DECLARE
numrows integer;

BEGIN
  select count(*) into numrows from markertemplates where game_id = v_gameid;
  if numrows = 0 then
    return 2;
  end if;
  select count(*) into numrows from markergame inner join markertemplates on markergame.uuid_1 = markertemplates.uuid where markertemplates.game_id = v_gameid;
  /* do not delete the game if the vault refers to it */
  if numrows = 0 then
    delete from markertemplates where game_id = v_gameid;
    return 0;
  else
    return 1;
  end if;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.deletemarkergame(v_gameid numeric) OWNER TO moss;

--
-- Name: deleteplayer(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION deleteplayer(v_ki numeric, OUT v_parent numeric, OUT v_child numeric, OUT v_notify numeric) RETURNS SETOF record
    AS $$
declare
  v_nodeid numeric;
  v_nodetype integer;
  v_nodes numeric;
  v_agelink numeric;
  v_ageinfo numeric;
  v_agenode numeric;
  v_ageowners numeric;
  v_inbox numeric;
  v_playerinfonode numeric;
  v_agejournalfolders noderefs;
  v_markergametemplate text;  
  v_noderefs noderefs;
  
begin

/*
PLAYER (v_ki)
  PlayerInfoNode
  BuddyList
  AgeJournals
  AvatarCloset
  Chronicle
  AgesIOwn
  AgesICanVisit
  IgnoreList
  Inbox
  PlayerInvite
  PIKA
  AvatarOutfit

*/

  /* retrieve playerinfo node */
  select nodeid from playerinfo where ki = v_ki into v_playerinfonode;

  /* remove us from AllPlayers list */
  delete from noderefs where parent = (select nodeid from playerinfolist where type = 12 limit 1) and child = v_playerinfonode;

/*  Return a list of removenodes to send notifies.
      Returns <parent, child, PlayerNode to notify (owner of the list)>

      This handles Buddy(2), Ignore(3) and PIKA(4) lists.
      
      Joined with the connected table, so that only connected players will get notifies.
  */
  return query (select nr.parent, nr.child, pil.creatorid from noderefs nr 
                inner join playerinfolist pil on nr.parent = pil.nodeid
                inner join connected c on c.id = pil.creatorid
                where pil.type in (2,3,4) and nr.child = v_playerinfonode);

  /* retrieve the inbox */
  select nodeid from folder inner join noderefs on folder.nodeid = noderefs.child where 
    noderefs.parent = v_ki and folder.type = 1 limit 1 into v_inbox;

 /* AgeJournalsFolder node */
  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
    noderefs.parent = v_ki and folder.type = 14 limit 1 into v_nodeid;
  /* child nodes */
  for v_agejournalfolders in select * from fetchnoderefs(v_nodeid) order by parent desc
  loop
    if (select type from nodes where nodeid = v_agejournalfolders.child) = 35 then /* special case - marker game */
      if (select count(parent) from noderefs where child = v_agejournalfolders.child) = 1 then
        /* No one else has this game, so let us delete it */
        select uuid_1 from markergame where nodeid = v_agejournalfolders.child into v_markergametemplate;
        delete from noderefs where parent = v_inbox and child = v_agejournalfolders.child; /* remove link from inbox so game can be deleted */
        delete from markertemplates where uuid = v_markergametemplate;
        PERFORM removenode(v_agejournalfolders.parent, v_agejournalfolders.child);
      else
        PERFORM removenode(v_agejournalfolders.parent, v_agejournalfolders.child);
      end if;       
    else 
    PERFORM removenode(v_agejournalfolders.parent, v_agejournalfolders.child);
    end if;
  end loop;
  PERFORM removenode(v_ki, v_nodeid);

  /* AgesICanVisitFolder */
  SELECT nodeid FROM ageinfolist INNER JOIN noderefs ON ageinfolist.nodeid = noderefs.child where 
    noderefs.parent = v_ki and ageinfolist.type = 24 limit 1 into v_nodeid;
  for v_agelink in select child from noderefs where parent = v_nodeid /* get agelinks */
  loop
    select child from noderefs where parent = v_agelink into v_ageinfo;
    /* remove us from CanVisit of ages we can visit */
    
    /* notifies to owners that this ref is gone */
    for v_ageowners in 
     (select ki from playerinfo pi inner join connected c on pi.ki = c.id where nodeid in (select child from noderefs where parent = (SELECT nodeid FROM
      playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where noderefs.parent = v_ageinfo and playerinfolist.type = 19)) and ki
      != (select ki from playerinfo where nodeid = v_playerinfonode))
    loop
      return query (select parent, child, v_ageowners from noderefs where parent = (SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON 
      playerinfolist.nodeid = noderefs.child where noderefs.parent = v_ageinfo and playerinfolist.type = 18));
    end loop;      

    /* and now do the delete */
    delete from noderefs where parent = (SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON 
      playerinfolist.nodeid = noderefs.child where noderefs.parent = v_ageinfo and playerinfolist.type = 18)
      and child = v_playerinfonode;
    delete from noderefs where parent = v_agelink and child = v_ageinfo;  /* remove agelink -> ageinfo noderef */
    PERFORM removenode(v_nodeid, v_agelink);  /* remove agelink */
  end loop;
  PERFORM removenode(v_ki, v_nodeid);

  /* AgesIOwn folder */
  SELECT nodeid FROM ageinfolist INNER JOIN noderefs ON ageinfolist.nodeid = noderefs.child where 
    noderefs.parent = v_ki and ageinfolist.type = 23 limit 1 into v_nodeid;  
  for v_agelink in select child from noderefs where parent = v_nodeid /* get agelinks */
  loop
    /* remove us from AgeOwners of this age */
    select child from noderefs where parent = v_agelink into v_ageinfo; -- get ageinfo
    if (select String64_2 from ageinfo where nodeid = v_ageinfo) = 'Neighborhood' then
      /* this is the player's neighborhood - need to notify other members this player is gone*/
      return query (
        select nr.parent, v_playerinfonode, pi.ki from noderefs nr inner join playerinfo pi on nr.child = pi.nodeid
        inner join connected c on c.id = pi.ki
        where parent = (select nodeid from playerinfolist inner join noderefs on 
          playerinfolist.nodeid = noderefs.child where noderefs.parent = v_ageinfo and playerinfolist.type = 19)
          and pi.ki != (select v_ki from playerinfo where nodeid = v_playerinfonode) /* do not need to notify ourselves */
      ); 
    end if;
    delete from noderefs where parent = (SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON
      playerinfolist.nodeid = noderefs.child where noderefs.parent = v_ageinfo and playerinfolist.type = 19)
      and child = v_playerinfonode;
    /* do not unlink or delete age here.  removenode() does it for us for AgesIOwn -> agelink
       removals (deleting book from shelf). */
    PERFORM removenode(v_nodeid, v_agelink); /* remove the link */
  end loop;
  PERFORM removenode(v_ki, v_nodeid);  
  
  /* Avatar outfit folder */
  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
    noderefs.parent = v_ki and folder.type = 7 limit 1 into v_nodeid;
  for v_nodes in select child from noderefs where parent = v_nodeid
  loop
    PERFORM removenode(v_nodeid, v_nodes);
  end loop;
  PERFORM removenode(v_ki, v_nodeid);

  /* Avatar closet folder */
  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
    noderefs.parent = v_ki and folder.type = 25 limit 1 into v_nodeid;
  for v_nodes in select child from noderefs where parent = v_nodeid
  loop
    PERFORM removenode(v_nodeid, v_nodes);
  end loop;
  PERFORM removenode(v_ki, v_nodeid);

  /* BuddyList folder */
  SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where 
    noderefs.parent = v_ki and playerinfolist.type = 2 limit 1 into v_nodeid;
  for v_nodes in select child from noderefs where parent = v_nodeid
  loop
    delete from noderefs where parent = v_nodeid and child = v_nodes;
   /* no deleting nodes here!  These are PlayerInfo nodes. */
  end loop;
  PERFORM removenode(v_ki, v_nodeid);

  /* Chronicle node */
  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
    noderefs.parent = v_ki and folder.type = 6 limit 1 into v_nodeid;
  /* child nodes */
  for v_noderefs in select * from fetchnoderefs(v_nodeid) order by parent desc
  loop
    PERFORM removenode(v_noderefs.parent, v_noderefs.child);
  end loop;
  /* unlink and delete the Chronicle node */
  PERFORM removenode(v_ki, v_nodeid);

  /* PIKA folder */
  SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where 
    noderefs.parent = v_ki and playerinfolist.type = 4 limit 1 into v_nodeid;
  for v_nodes in select child from noderefs where parent = v_nodeid
  loop
    delete from noderefs where parent = v_nodeid and child = v_nodes;
   /* no deleting nodes here!  These are PlayerInfo nodes. */
  end loop;
  PERFORM removenode(v_ki, v_nodeid);

  /* PlayerInvite folder */
  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
    noderefs.parent = v_ki and folder.type = 28 limit 1 into v_nodeid;
  /* child nodes */
  for v_nodes in select child from noderefs where parent = v_nodeid
  loop
    delete from noderefs where parent = v_nodeid and child = v_noderefs.child;
   /* Check to see if deletion is needed when a sample is available - just unlinking for now */
  end loop;
  PERFORM removenode(v_ki, v_nodeid);

/* Inbox */
  for v_noderefs in select * from fetchnoderefs(v_inbox) order by parent desc
  loop
    /* we check here because we need to delete this game if we have the only ref - even if it is not our game */
    if (select type from nodes where nodeid = v_noderefs.child) = 35 then /* special case - marker game */
      if (select count(parent) from noderefs where child = v_noderefs.child) = 1 then
        /* No one else has this game, so let us delete it */
        select uuid_1 from markergame where nodeid = v_noderefs.child into v_markergametemplate;
        delete from markertemplates where uuid = v_markergametemplate;
        PERFORM removenode(v_noderefs.parent, v_noderefs.child);
      else
        PERFORM removenode(v_noderefs.parent, v_noderefs.child);
      end if;      
    else
      PERFORM removenode(v_noderefs.parent, v_noderefs.child);
    end if;
  end loop;
  PERFORM removenode(v_ki, v_nodeid);
  
/* IgnoreList folder */
  SELECT nodeid FROM playerinfolist INNER JOIN noderefs ON playerinfolist.nodeid = noderefs.child where 
    noderefs.parent = v_ki and playerinfolist.type = 3 limit 1 into v_nodeid;
  for v_nodes in select child from noderefs where parent = v_nodeid
  loop
    delete from noderefs where parent = v_nodeid and child = v_nodes;
   /* no deleting nodes here!  These are PlayerInfo nodes. */
  end loop; 
  PERFORM removenode(v_ki, v_nodeid);

  /* delete any CGZ maker games - no markergame node for these */
  delete from markertemplates where owner = v_ki and type = 1;

  /* unlink the System node */
  delete from noderefs where parent = v_ki and child = (select nodeid from System limit 1);

  /*  delete any PelletScores we own */
  delete from scores where holder = v_playerinfonode;
  
  /* delete PlayerInfoNode */
  PERFORM removenode (v_ki, v_playerinfonode);

  /* finally, delete the player node */
  delete from nodes where nodeid = v_ki;

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.deleteplayer(v_ki numeric, OUT v_parent numeric, OUT v_child numeric, OUT v_notify numeric) OWNER TO moss;

--
-- Name: do_we_own_node(numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION do_we_own_node(v_nodeid numeric, v_ki numeric) RETURNS boolean
    AS $$
/* 
   checks to see if the creatorid of the node entered is equal to
   the playerid.  If it is, returns true, else returns false.
*/

DECLARE
   v_type integer;
   v_creatorid numeric;
   v_table text;

BEGIN
  select type from nodes where nodeid = v_nodeid into v_type;
  if v_type = 3 then /* age node */
    v_table := 'age';
  elseif v_type = 33 then
    v_table := 'ageinfo';
  elseif v_type = 34 then
    v_table := 'ageinfolist';
  elseif v_type = 28 then
    v_table := 'agelink';
  elseif v_type = 29 then
    v_table := 'chronicle';
  elseif v_type = 22 then
    v_table := 'folder';
  elseif v_type = 25 then
    v_table := 'image';
  elseif v_type = 35 then
    v_table := 'markergame';
  elseif v_type = 2 then
    v_table := 'player';
  elseif v_type = 23 then
    v_table := 'playerinfo';
  elseif v_type = 30 then
    v_table := 'playerinfolist';
  elseif v_type = 27 then
    v_table := 'sdl';
  elseif v_type = 24 then
    v_table := 'system';
  elseif v_type = 26 then
    v_table := 'textnote';
  else
    return false;
  end if;

EXECUTE 'select creatorid from ' || v_table || ' where nodeid = ' || v_nodeid  into v_creatorid;

if v_creatorid = v_ki then
  return true;
else
  return false;
end if;

return false;
  
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.do_we_own_node(v_nodeid numeric, v_ki numeric) OWNER TO moss;

--
-- Name: egg1award(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION egg1award(v_ki numeric, OUT v_parent numeric, OUT v_child numeric) RETURNS record
    AS $$

DECLARE
  v_game numeric;
  v_nodeid numeric;
  v_agejournalfolders noderefs;
  c_null_uuid constant CHARACTER(36) := '00000000-0000-0000-0000-000000000000';
  c_game_uuid constant CHARACTER(36) := '25252525-2525-2525-2525-252525252525';

BEGIN

  v_parent := 0;
  v_child := 0;

  /* make sure the game exists */
  SELECT v_gameid FROM getmarkergame(c_game_uuid) INTO v_game;
  if v_game is null then
    PERFORM egg1setup();
  end if;
  SELECT nodeid FROM markergame where uuid_1=c_game_uuid limit 1 into v_child;
  if v_child is null then
    /* build the node */
    SELECT * FROM newnodeid(35) INTO v_child;
    INSERT INTO markergame VALUES(v_child, now(), now(), c_null_uuid, 'Personal', c_null_uuid, 0, '25 markers for a quiet night in Relto', c_game_uuid);
  end if;

  /* see if they have the game already */
  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
    noderefs.parent = v_ki and folder.type = 14 limit 1 into v_nodeid;
  /* child nodes */
  for v_agejournalfolders in select * from fetchnoderefs(v_nodeid) order by parent desc
  loop
    if (select type from nodes where nodeid = v_agejournalfolders.child) = 35 then /* marker game */
      if (select uuid_1 from markergame where nodeid = v_agejournalfolders.child) = c_game_uuid then
        return;
      end if;
    end if;
  end loop;

  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child where 
    noderefs.parent = v_ki and folder.type = 1 limit 1 into v_nodeid;
  SELECT markergame.nodeid from noderefs INNER JOIN markergame ON noderefs.child = markergame.nodeid where noderefs.parent = v_nodeid and markergame.uuid_1=c_game_uuid INTO v_game;
  if v_game is not null then
    return;
  end if;

  /* if we get here they don't have the game, put it in their inbox */
  v_parent := v_nodeid;
  PERFORM addnode(v_parent, v_child, v_ki);

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.egg1award(v_ki numeric, OUT v_parent numeric, OUT v_child numeric) OWNER TO moss;

--
-- Name: egg1setup(); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION egg1setup() RETURNS void
    AS $$

DECLARE
  v_game numeric;

BEGIN

  SELECT v_gameid FROM createmarkergame(0, 0, '25 markers for a quiet night in Relto') INTO v_game;
  UPDATE markertemplates SET uuid = '25252525-2525-2525-2525-252525252525', next_number = 112 WHERE game_id = v_game;
  INSERT INTO markers VALUES(v_game, -27.6924819946289, 128.401458740234, -8.47756862640381, 2, 'for Kierra?', 'Personal');
  INSERT INTO markers VALUES(v_game, -20.6176605224609, 108.222236633301, -2.81310057640076, 3, 'top o'' the isle', 'Personal');
  INSERT INTO markers VALUES(v_game, -67.4551086425781, 44.2196426391602, -6.62701082229614, 12, 'Look at your trees in first person!', 'Personal');
  INSERT INTO markers VALUES(v_game, -31.7185955047607, 68.0172348022461, -1.05153107643127, 16, 'Hide ''n'' seek', 'Personal');
  INSERT INTO markers VALUES(v_game, 11.2535600662231, -1.88806068897247, 10.6348724365234, 19, 'longing for a swim', 'Personal');
  INSERT INTO markers VALUES(v_game, -3.24080491065979, -2.42856216430664, 9.88113689422607, 20, 'I got nothin'' to say', 'Personal');
  INSERT INTO markers VALUES(v_game, 7.1518292427063, -20.3621025085449, 8.84820079803467, 23, 'tree', 'Personal');
  INSERT INTO markers VALUES(v_game, -11.7704601287842, -8.35681056976318, 8.44188499450684, 26, 'blip goes the marker!', 'Personal');
  INSERT INTO markers VALUES(v_game, -15.4304342269897, -8.25783920288086, 7.81380891799927, 27, 'could use a better name', 'Personal');
  INSERT INTO markers VALUES(v_game, -14.5503711700439, -12.8220949172974, 7.60635852813721, 28, 'The "Er''cana plants''', 'Personal');
  INSERT INTO markers VALUES(v_game, 3.12835240364075, 4.67205333709717, 10.9255571365356, 40, 'In the Middle, In the Middle, In the Middle', 'Personal');
  INSERT INTO markers VALUES(v_game, -30.4680118560791, -12.813404083252, -1.36299705505371, 63, 'edgy', 'Personal');
  INSERT INTO markers VALUES(v_game, 11.5889987945557, 11.2614622116089, 11.2894649505615, 65, 'I got nothin'' to say', 'Personal');
  INSERT INTO markers VALUES(v_game, 31.9351692199707, -41.7478790283203, -2.63408589363098, 75, 'dock', 'Personal');
  INSERT INTO markers VALUES(v_game, 36.5694389343262, 20.9085102081299, 13.5605564117432, 87, 'inside', 'Personal');
  INSERT INTO markers VALUES(v_game, 73.6486892700195, -2.27535700798035, 19.2839450836182, 94, 'Hey, underwater grass!', 'Personal');
  INSERT INTO markers VALUES(v_game, 46.6628684997559, -30.2678985595703, 13.7383003234863, 95, 'Good thing the D''ni built to last, ''cuz we''re standing on their TVs.', 'Personal');
  INSERT INTO markers VALUES(v_game, 19.0391693115234, 74.4392547607422, 4.05051469802856, 97, 'watch out for the big spike...', 'Personal');
  INSERT INTO markers VALUES(v_game, 47.9609489440918, 50.606201171875, 0.913627982139587, 99, 'I got nothin'' to say', 'Personal');
  INSERT INTO markers VALUES(v_game, 36.0439796447754, 11.678822517395, 13.1501817703247, 100, 'no collision here, collision on the other one...', 'Personal');
  INSERT INTO markers VALUES(v_game, 63.4698944091797, 45.734073638916, 8.91251277923584, 101, 'I like this corner, but I wish we could sit up on the hills.', 'Personal');
  INSERT INTO markers VALUES(v_game, 60.8664436340332, -41.3032569885254, 11.6552295684814, 105, 'fog top view', 'Personal');
  INSERT INTO markers VALUES(v_game, 86.5986404418945, -40.9102668762207, 5.0979585647583, 106, 'This game can be completed with three relinks.', 'Personal');
  INSERT INTO markers VALUES(v_game, 16.3346748352051, -20.9124355316162, 7.56990242004395, 107, 'I got nothin'' to say', 'Personal');
  INSERT INTO markers VALUES(v_game, -58.0759620666504, -61.6226463317871, 9.84555244445801, 110, 'I like my clock', 'Personal');

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.egg1setup() OWNER TO moss;

--
-- Name: fetchnode(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION fetchnode(v_nodeid numeric, OUT v_nodetype integer, OUT v_createtime integer, OUT v_modifytime integer, OUT v_createagename text, OUT v_createageuuid character, OUT v_creatoracctid character, OUT v_creatorid numeric, OUT v_uuid_1 character, OUT v_uuid_2 character, OUT v_filename text, OUT v_int32_1 numeric, OUT v_int32_2 numeric, OUT v_int32_3 numeric, OUT v_uint32_1 numeric, OUT v_uint32_2 numeric, OUT v_uint32_3 numeric, OUT v_string64_1 text, OUT v_string64_2 text, OUT v_string64_3 text, OUT v_string64_4 text, OUT v_text_1 text, OUT v_type integer, OUT v_linkpoints text, OUT v_exists integer, OUT v_name text, OUT v_value text, OUT v_gender text, OUT v_online integer, OUT v_ki numeric, OUT v_blob bytea, OUT v_title text, OUT v_image bytea) RETURNS record
    AS $$

/* This function returns a node. Whee! */

DECLARE
  ntype integer;
  /* Junk vars  used so select * will work */
  id numeric;

  /* these are for time conversion */
  v_createtimecvt timestamp without time zone;
  v_modifytimecvt timestamp without time zone;
  
BEGIN
  /* Check to see if this node exists in master node table, and if it does get the type.
     If it does not exist, exit function.  In this case, nodetype will be <null>, so the
     caller can check this value before proceeding. */
  
  select type from nodes where nodeid = v_nodeid into ntype;
  if ntype is null then
    return; /* Node not found.  Exit function with null record returned. */
  end if;
  
  if ntype = 3 then /* age node */
    select 3, * from age where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_creatoracctid, v_creatorid, v_uuid_1, v_uuid_2, v_filename;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 33 then /* ageinfo node */
    select 33, * from ageinfo where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_creatoracctid, v_creatorid, v_int32_1, v_int32_2, v_int32_3, v_uint32_1,
      v_uint32_2, v_uint32_3, v_uuid_1, v_uuid_2, v_string64_2, v_string64_3, v_string64_4, v_text_1;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 34 then /* ageinfolist node */
    select 34, * from ageinfolist where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_creatoracctid, v_creatorid, v_type;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 28 then /* agelink node */
    select 28, * from agelink where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_createageuuid, v_createagename, v_creatoracctid, v_creatorid, v_int32_1, v_int32_2, v_linkpoints;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;
  
  elseif ntype = 29 then /* chronicle node */
    select 29, * from chronicle where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_createageuuid, v_createagename, v_creatoracctid, v_creatorid, v_type, v_name, v_value;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 22 then /* folder node */
    select 22, * from folder where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_createageuuid, v_createagename, v_creatoracctid, v_creatorid, v_type, v_name;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 25 then /* image node */
    select 25, * from image where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_createageuuid, v_createagename, v_creatoracctid, v_creatorid, v_exists, v_name, v_image;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 35 then /* markergame node ( UU/PotS calls this MarkerList) */
    select 35, * from markergame where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_createageuuid, v_createagename, v_creatoracctid, v_creatorid, v_name, v_uuid_1;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 2 then /* player node */
    select 2, * from player where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_creatoracctid, v_creatorid, v_int32_1, v_int32_2, v_uint32_1, v_uuid_1, v_uuid_2, v_gender, v_name;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 23 then /* playerinfo node */
    select 23, * from playerinfo where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_creatoracctid, v_creatorid, v_online, v_ki, v_uuid_1, v_string64_1, v_name;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 30 then /* playerinfolist */
    select 30, * from playerinfolist where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_creatoracctid, v_creatorid, v_type;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 27 then /* sdl node */
    select 27, * from sdl where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_createageuuid, v_createagename, v_creatoracctid, v_creatorid, v_int32_1, v_name, v_blob;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 24 then /* system node */
    select 24, * from system where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_creatoracctid, v_creatorid;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;

  elseif ntype = 26 then /* textnote node */
    select 26, * from textnote where nodeid = v_nodeid into v_nodetype, id, v_createtimecvt, v_modifytimecvt, v_createageuuid, v_createagename, v_creatoracctid, v_creatorid, v_int32_1, v_int32_2, v_title, v_value;
    v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
    v_modifytime := trunc(EXTRACT(EPOCH FROM v_modifytimecvt));
    return;
  end if;

  return; /* fall though return - we should not get here */

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.fetchnode(v_nodeid numeric, OUT v_nodetype integer, OUT v_createtime integer, OUT v_modifytime integer, OUT v_createagename text, OUT v_createageuuid character, OUT v_creatoracctid character, OUT v_creatorid numeric, OUT v_uuid_1 character, OUT v_uuid_2 character, OUT v_filename text, OUT v_int32_1 numeric, OUT v_int32_2 numeric, OUT v_int32_3 numeric, OUT v_uint32_1 numeric, OUT v_uint32_2 numeric, OUT v_uint32_3 numeric, OUT v_string64_1 text, OUT v_string64_2 text, OUT v_string64_3 text, OUT v_string64_4 text, OUT v_text_1 text, OUT v_type integer, OUT v_linkpoints text, OUT v_exists integer, OUT v_name text, OUT v_value text, OUT v_gender text, OUT v_online integer, OUT v_ki numeric, OUT v_blob bytea, OUT v_title text, OUT v_image bytea) OWNER TO moss;

--
-- Name: fetchnoderefs(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION fetchnoderefs(v_nodeid numeric) RETURNS SETOF noderefs
    AS $$

/* This function fetches a list of node refs */

DECLARE
v_noderefs noderefs;

BEGIN

for v_noderefs in
      select * from noderefs where parent = v_nodeid order by parent
      loop
        return next v_noderefs;
        for v_noderefs in
              select * from fetchnoderefs(v_noderefs.child) order by parent
        loop
              return next v_noderefs;
        end loop;   
       end loop;
return;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.fetchnoderefs(v_nodeid numeric) OWNER TO moss;

--
-- Name: getagebyuuid(character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION getagebyuuid(v_uuid character, OUT v_agenode numeric, OUT v_ageinfo numeric, OUT v_filename text) RETURNS record
    AS $$

/* returns age node, ageinfo node, and age filename */

DECLARE
v_childnode numeric;
v_holder numeric;

BEGIN
  select nodeid, filename from age where uuid_1 = v_uuid limit 1 into v_agenode, v_filename;
  if v_agenode is NULL then
    v_agenode = 0;
    v_filename = '';
  end if;

  if v_agenode != 0 then
    for v_childnode in
      select child from noderefs where parent = v_agenode
      loop
        select nodeid from nodes where nodeid = v_childnode and type = 33 into v_holder;
        if v_holder is not null then
          v_ageinfo = v_holder;
        end if;
      end loop;
    else
      v_ageinfo = null;
  end if;
  return;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.getagebyuuid(v_uuid character, OUT v_agenode numeric, OUT v_ageinfo numeric, OUT v_filename text) OWNER TO moss;

--
-- Name: getagesdl(numeric, character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION getagesdl(v_ageinfo numeric, v_name character, OUT v_sdl bytea) RETURNS bytea
    AS $$

BEGIN
  select blob from sdl inner join noderefs on sdl.nodeid = noderefs.child where noderefs.parent = v_ageinfo and sdl.name = v_name limit 1 into v_sdl;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.getagesdl(v_ageinfo numeric, v_name character, OUT v_sdl bytea) OWNER TO moss;

--
-- Name: getglobalsdlbyname(character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION getglobalsdlbyname(v_name character, OUT v_sdl bytea) RETURNS bytea
    AS $$

DECLARE
v_allagesdlnode numeric;
v_globalsdls numeric;
v_sdlname text;

BEGIN
select nodeid from folder where type = 20 limit 1 into v_allagesdlnode;
for v_globalsdls in
  select child from noderefs where parent = v_allagesdlnode
  loop
    select name from sdl where nodeid = v_globalsdls into v_sdlname;
    if v_sdlname = v_name then
      select blob from sdl where nodeid = v_globalsdls into v_sdl;
    end if;
  end loop;
  return;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.getglobalsdlbyname(v_name character, OUT v_sdl bytea) OWNER TO moss;

--
-- Name: getmarkergame(character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION getmarkergame(v_uuid character, OUT v_type numeric, OUT v_name character, OUT v_gameid numeric) RETURNS record
    AS $$

BEGIN
  select type, name, game_id into v_type, v_name, v_gameid from markertemplates where uuid = v_uuid limit 1;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.getmarkergame(v_uuid character, OUT v_type numeric, OUT v_name character, OUT v_gameid numeric) OWNER TO moss;

--
-- Name: getmarkers(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION getmarkers(v_gameid numeric, OUT v_id numeric, OUT v_x double precision, OUT v_y double precision, OUT v_z double precision, OUT v_name character, OUT v_age character) RETURNS SETOF record
    AS $$

DECLARE
marker record;

BEGIN
  for marker in
    select x, y, z, marker_number, marker_name, age_name from markers where game_id = v_gameid order by marker_number loop
      v_id := marker.marker_number;
      v_x := marker.x;
      v_y := marker.y;
      v_z := marker.z;
      v_name := marker.marker_name;
      v_age := marker.age_name;
      return next;
    end loop;
  return;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.getmarkers(v_gameid numeric, OUT v_id numeric, OUT v_x double precision, OUT v_y double precision, OUT v_z double precision, OUT v_name character, OUT v_age character) OWNER TO moss;

--
-- Name: getpublicagelist(text); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION getpublicagelist(v_filename text, OUT v_uuid character, OUT v_instance_name text, OUT v_user_defined text, OUT v_display_name text, OUT v_instance_num numeric, OUT v_numowners numeric) RETURNS SETOF record
    AS $$

DECLARE
v_pubages record;

BEGIN
  for v_pubages in
    select nodeid, modifytime, int32_1, uuid_1, string64_2, string64_3, string64_4, text_1 from ageinfo where string64_2 = v_filename and int32_2 = 1 order by modifytime DESC limit 50 loop
     /* MOUL returns max 50 records, so we limit 50 here to duplicate that */
      v_uuid := v_pubages.uuid_1;
      v_instance_name := v_pubages.string64_3;
      v_user_defined := v_pubages.string64_4;
      v_display_name := v_pubages.text_1;
      v_instance_num := v_pubages.int32_1;
      v_numowners := (select count(child) from noderefs where parent = (
        select nodeid from playerinfolist inner join noderefs on playerinfolist.nodeid = noderefs.child where 
        noderefs.parent = v_pubages.nodeid and playerinfolist.type = 19 limit 1)); 

      return next;
    end loop;
  return;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.getpublicagelist(v_filename text, OUT v_uuid character, OUT v_instance_name text, OUT v_user_defined text, OUT v_display_name text, OUT v_instance_num numeric, OUT v_numowners numeric) OWNER TO moss;

--
-- Name: getscore(numeric, text); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION getscore(v_holder numeric, v_name text, OUT v_id numeric, OUT v_createtime integer, OUT v_type integer, OUT v_score numeric) RETURNS record
    AS $$

/* This function reads a score record. */

DECLARE
  v_createtimecvt timestamp without time zone;

BEGIN
  select id, createtime, type, score from scores where holder=v_holder and name=v_name into v_id, v_createtimecvt, v_type, v_score limit 1;
  if v_id is null then
    return; /* no score found */
  end if;
  v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
  
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.getscore(v_holder numeric, v_name text, OUT v_id numeric, OUT v_createtime integer, OUT v_type integer, OUT v_score numeric) OWNER TO moss;

--
-- Name: getuuidforsdl(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION getuuidforsdl(v_childnode numeric, OUT v_uuid text) RETURNS text
    AS $$

BEGIN
  /* XXX is this correct? I believe it must be - but only if this is only
     called for sdl; if we make it more general this is obviously wrong */
  select createageuuid from sdl where nodeid=v_childnode into v_uuid limit 1;
  /* longer version */
  /*select uuid_1 from ageinfo inner join noderefs on ageinfo.nodeid = nodrefs.parent where noderefs.child = v_childnode int v_uuid limit 1;*/
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.getuuidforsdl(v_childnode numeric, OUT v_uuid text) OWNER TO moss;

--
-- Name: initvault(); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION initvault() RETURNS integer
    AS $$
/*
  This function will create the initial vault nodes in a clean
  vault.
*/

DECLARE
  v_sysnode NUMERIC;
  v_gibnode NUMERIC;
  v_nodeid NUMERIC;
  v_holder INTEGER; /* temporary storage */
  v_status INTEGER;
  v_age_uuid CHARACTER(36);
  v_holdnodeid NUMERIC;
  v_hoodnodeid NUMERIC;
  v_hoodagedevices NUMERIC;
  c_admin_uuid CHARACTER(36);
  c_null_uuid constant CHARACTER(36) := '00000000-0000-0000-0000-000000000000';  /* using c_ to signify constants */
  c_welcometitle text;
  c_welcometext text;
  c_sharperjournal text;
  c_gzimage bytea;

BEGIN
  /* make sure the table of connected players is clear XXX good idea? */

  v_status := 0;  /* set initial return status to "no error" */
    
  /* set constants */
  /* Many of the initial nodes are created by a UUID, so I am going to use the
     admin TABLE FOR this.  Perhaps this is what this is for, anyway. /shrug  */
  SELECT uuid_1 FROM admin WHERE NAME = 'mossadmin' INTO c_admin_uuid;
  
  if c_admin_uuid IS NULL THEN
    c_admin_uuid := uuid();
    INSERT INTO admin VALUES ('mossadmin', now(), now(), c_admin_uuid);
  END if;  

  /* I could define these as constants, but this makes it very simple to change the initial message text */
  c_welcometitle = 'Welcome';
  c_welcometext := E'Welcome to MOSS';
  c_sharperjournal := E'<cover src=\"xSharperJournalCover*1#0.hsm\"><font size=18 face=Sharper color=982A2A><margin left=62 right=62 top=48>4.5.11 - Someone seems to have run off with my journal.';

  c_gzimage := E'\\175\\002\\000\\000\\171\\002\\000\\000\\377\\330\\377\\340\\000\\020\\112\\106\\111\\106\\000\\001\\001\\001\\000\\140\\000\\140\\000\\000\\377\\333\\000\\103\\000\\010\\006\\006\\007\\006\\005\\010\\007\\007\\007\\011\\011\\010\\012\\014\\024\\015\\014\\013\\013\\014\\031\\022\\023\\017\\024\\035\\032\\037\\036\\035\\032\\034\\034\\040\\044\\056\\047\\040\\042\\054\\043\\034\\034\\050\\067\\051\\054\\060\\061\\064\\064\\064\\037\\047\\071\\075\\070\\062\\074\\056\\063\\064\\062\\377\\333\\000\\103\\001\\011\\011\\011\\014\\013\\014\\030\\015\\015\\030\\062\\041\\034\\041\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\062\\377\\300\\000\\021\\010\\000\\001\\000\\001\\003\\001\\042\\000\\002\\021\\001\\003\\021\\001\\377\\304\\000\\037\\000\\000\\001\\005\\001\\001\\001\\001\\001\\001\\000\\000\\000\\000\\000\\000\\000\\000\\001\\002\\003\\004\\005\\006\\007\\010\\011\\012\\013\\377\\304\\000\\265\\020\\000\\002\\001\\003\\003\\002\\004\\003\\005\\005\\004\\004\\000\\000\\001\\175\\001\\002\\003\\000\\004\\021\\005\\022\\041\\061\\101\\006\\023\\121\\141\\007\\042\\161\\024\\062\\201\\221\\241\\010\\043\\102\\261\\301\\025\\122\\321\\360\\044\\063\\142\\162\\202\\011\\012\\026\\027\\030\\031\\032\\045\\046\\047\\050\\051\\052\\064\\065\\066\\067\\070\\071\\072\\103\\104\\105\\106\\107\\110\\111\\112\\123\\124\\125\\126\\127\\130\\131\\132\\143\\144\\145\\146\\147\\150\\151\\152\\163\\164\\165\\166\\167\\170\\171\\172\\203\\204\\205\\206\\207\\210\\211\\212\\222\\223\\224\\225\\226\\227\\230\\231\\232\\242\\243\\244\\245\\246\\247\\250\\251\\252\\262\\263\\264\\265\\266\\267\\270\\271\\272\\302\\303\\304\\305\\306\\307\\310\\311\\312\\322\\323\\324\\325\\326\\327\\330\\331\\332\\341\\342\\343\\344\\345\\346\\347\\350\\351\\352\\361\\362\\363\\364\\365\\366\\367\\370\\371\\372\\377\\304\\000\\037\\001\\000\\003\\001\\001\\001\\001\\001\\001\\001\\001\\001\\000\\000\\000\\000\\000\\000\\001\\002\\003\\004\\005\\006\\007\\010\\011\\012\\013\\377\\304\\000\\265\\021\\000\\002\\001\\002\\004\\004\\003\\004\\007\\005\\004\\004\\000\\001\\002\\167\\000\\001\\002\\003\\021\\004\\005\\041\\061\\006\\022\\101\\121\\007\\141\\161\\023\\042\\062\\201\\010\\024\\102\\221\\241\\261\\301\\011\\043\\063\\122\\360\\025\\142\\162\\321\\012\\026\\044\\064\\341\\045\\361\\027\\030\\031\\032\\046\\047\\050\\051\\052\\065\\066\\067\\070\\071\\072\\103\\104\\105\\106\\107\\110\\111\\112\\123\\124\\125\\126\\127\\130\\131\\132\\143\\144\\145\\146\\147\\150\\151\\152\\163\\164\\165\\166\\167\\170\\171\\172\\202\\203\\204\\205\\206\\207\\210\\211\\212\\222\\223\\224\\225\\226\\227\\230\\231\\232\\242\\243\\244\\245\\246\\247\\250\\251\\252\\262\\263\\264\\265\\266\\267\\270\\271\\272\\302\\303\\304\\305\\306\\307\\310\\311\\312\\322\\323\\324\\325\\326\\327\\330\\331\\332\\342\\343\\344\\345\\346\\347\\350\\351\\352\\362\\363\\364\\365\\366\\367\\370\\371\\372\\377\\332\\000\\014\\003\\001\\000\\002\\021\\003\\021\\000\\077\\000\\311\\242\\212\\053\\352\\217\\237\\077\\377\\331';

  SELECT COUNT(nodeid) FROM system INTO v_holder; /*check for preexisting system node */
  if v_holder > 0 THEN
    v_status := 1;
    return v_status;
  ELSE
    SELECT nextval('public.nodeid_seq') INTO v_sysnode;
    INSERT INTO nodes (nodeid, TYPE) VALUES (v_sysnode, 24);
    INSERT INTO system VALUES (v_sysnode, now(), now(), c_null_uuid, 0);
  END if;

  SELECT COUNT(nodeid) FROM folder WHERE TYPE = 30 INTO v_holder; /*check for preexisting GlobalInbox node */
  if v_holder > 0 THEN
    v_status := 1;
    return v_status;
  ELSE
    SELECT nextval('public.nodeid_seq') INTO v_gibnode;
    INSERT INTO nodes (nodeid, TYPE) VALUES (v_gibnode, 22);
    INSERT INTO folder VALUES (v_gibnode, now(), now(), NULL, NULL, c_null_uuid, 0, 30, NULL);
  END if;

  PERFORM addnode(v_sysnode, v_gibnode, 0);  /* system -> global inbox */

  /* I do not know if we need these below - using Alcugs as a guide */

  SELECT COUNT(nodeid) FROM playerinfolist WHERE TYPE = 12 INTO v_holder; /* check for AllPlayers folder */
  if v_holder > 0 THEN
    v_status := 1;
    return v_status;
  ELSE
    SELECT nextval('public.nodeid_seq') INTO v_nodeid;
    INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 30);
    INSERT INTO playerinfolist VALUES (v_nodeid, now(), now(), c_null_uuid, 0, 12);
  END if;

  SELECT COUNT(nodeid) FROM folder WHERE TYPE = 20 INTO v_holder; /* check for AllAgeGlobalSDLNodes folder */
  if v_holder > 0 THEN
    v_status := 1;
    return v_status;
  ELSE
    SELECT nextval('public.nodeid_seq') INTO v_nodeid;
    INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 22);
    INSERT INTO folder VALUES (v_nodeid, now(), now(), NULL, NULL, c_null_uuid, 0, 20, NULL);  
  END if;

  /* Add GlobalInbox nodes */

  /* Text note - Laxman "Welcome to the cavern" */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 26);
  INSERT INTO textnote VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 0, 0, c_welcometitle, c_welcometext);
  PERFORM addnode(v_gibnode, v_nodeid, 0); 

  /* DeviceInboxFolder - CommunityImager */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 22);
  INSERT INTO folder VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 10, 'CommunityImager');
  PERFORM addnode(v_gibnode, v_nodeid, 0); 

  /* Generic Folder - Journals */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 22);
  INSERT INTO folder VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 0, 'Journals');
  PERFORM addnode(v_gibnode, v_nodeid, 0); 

  /* Text Note - Sharper journal */
  v_holdnodeid := v_nodeid; /* save the last node id, so we can add the ref */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 26);
  INSERT INTO textnote VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 0, 0, 'Sharper', c_sharperjournal);
  PERFORM addnode(v_holdnodeid, v_nodeid, 0);  /* make this a child of the journals folder */

  /* DeviceInboxFolder - GZImager */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 22);
  INSERT INTO folder VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 10, 'GZImager');
  PERFORM addnode(v_gibnode, v_nodeid, 0);

  /* Image node - GZImage */
  v_holdnodeid := v_nodeid; /* save the last node id, so we can add the ref */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 25);
  INSERT INTO image VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 1, 'image', c_gzimage);
  PERFORM addnode(v_holdnodeid, v_nodeid, 0);  /* make this a child of the GZImager inbox folder */
  

  /* Generic Folder - MemorialImager */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 22);
  INSERT INTO folder VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 0, 'MemorialImager');
  PERFORM addnode(v_gibnode, v_nodeid, 0);

  /* Text note - MemorialImager */
  v_holdnodeid := v_nodeid; /* save the last node id, so we can add the ref */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 26);
  INSERT INTO textnote VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 0, 0, 'MemorialImager', 'MemorialImager text goes here');
  PERFORM addnode(v_holdnodeid, v_nodeid, 0);  /* make this a child of the MemorialImager folder */


  /* Add global scores. */
  PERFORM newscore(0, 'LakeScore', 2, 0);


  /*  Let us add two default ages. */

  /* create the initial Bevin */
  SELECT v_agenode FROM createage('Neighborhood', 'Bevin', 'DRC', '', uuid(), NULL) INTO v_hoodnodeid;

  /* get the AgeDevicesFolder for the Bevin */
  SELECT nodeid FROM folder INNER JOIN noderefs ON folder.nodeid = noderefs.child WHERE 
      noderefs.parent = v_hoodnodeid AND folder.TYPE = 15 limit 1 INTO v_hoodagedevices;

  /* create and link text note - DRCImager */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 26);
  INSERT INTO textnote VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 2, NULL,'DRCImager',NULL);
  PERFORM addnode(v_hoodagedevices, v_nodeid, 0);

  /* create and link DeviceInboxFolder for DRCImager */
  SELECT nextval('public.nodeid_seq') INTO v_holdnodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_holdnodeid, 22);
  INSERT INTO folder VALUES (v_holdnodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 10, 'DevInbox');
  PERFORM addnode(v_nodeid, v_holdnodeid, 0);

  /* create and link text note - D'ni Imager Left */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 26);
  INSERT INTO textnote VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 2, NULL,'D''ni  Imager Left',NULL);
  PERFORM addnode(v_hoodagedevices, v_nodeid, 0);

  /* create and link DeviceInboxFolder for D'ni Imager Left */
  SELECT nextval('public.nodeid_seq') INTO v_holdnodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_holdnodeid, 22);
  INSERT INTO folder VALUES (v_holdnodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 10, 'DevInbox');
  PERFORM addnode(v_nodeid, v_holdnodeid, 0); 

  /* create and link text note - D'ni Imager Right */
  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_nodeid, 26);
  INSERT INTO textnote VALUES (v_nodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 2, NULL,'D''ni  Imager Right',NULL);
  PERFORM addnode(v_hoodagedevices, v_nodeid, 0);

  /* create and link DeviceInboxFolder for D'ni Imager Right */
  SELECT nextval('public.nodeid_seq') INTO v_holdnodeid;
  INSERT INTO nodes (nodeid, TYPE) VALUES (v_holdnodeid, 22);
  INSERT INTO folder VALUES (v_holdnodeid, now(), now(), NULL, NULL, c_admin_uuid, 0, 10, 'DevInbox');
  PERFORM addnode(v_nodeid, v_holdnodeid, 0);

  /* create the global city - public flag set in createage() */
  PERFORM createage('city','Ae''gura', NULL, NULL, uuid(), NULL);

  /* create the guild pubs with specific UUIDs (from nxusBookMachine.py) - do not set public flag */
  PERFORM createage('GuildPub-Cartographers','GuildPub-Cartographers','GuildPub-Cartographers','GuildPub-Cartographers','35624301-841e-4a07-8db6-b735cf8f1f53',NULL);
  PERFORM createage('GuildPub-Greeters','GuildPub-Greeters','GuildPub-Greeters','GuildPub-Greeters','381fb1ba-20a0-45fd-9bcb-fd5922439d05',NULL);
  PERFORM createage('GuildPub-Maintainers','GuildPub-Maintainers','GuildPub-Maintainers','GuildPub-Maintainers','e8306311-56d3-4954-a32d-3da01712e9b5',NULL);
  PERFORM createage('GuildPub-Messengers','GuildPub-Messengers','GuildPub-Messengers','GuildPub-Messengers','9420324e-11f8-41f9-b30b-c896171a8712',NULL);
  PERFORM createage('GuildPub-Writers','GuildPub-Writers','GuildPub-Writers','GuildPub-Writers','5cf4f457-d546-47dc-80eb-a07cdfefa95d',NULL);

  /* create the public kveer - do not set public flag, but set specific UUID (from nxusBookMachine.py */
  PERFORM createage('Kveer','Kveer', NULL, '', '68e219e0-ee25-4df0-b855-0435584e29e2', NULL);
  
  /* create public Kirel - public flag set in createage() */
  PERFORM createage('Neighborhood02','Kirel', NULL, '', uuid(), NULL);

  /* create public GreatTreePub - public flag set in createage() */
  PERFORM createage('GreatTreePub','The Watcher''s Pub', NULL, '', uuid(), NULL);

  /* create Phil's Relto */
  PERFORM createage('philRelto','philRelto', 'philRelto', 'philRelto', 'e8a2aaed-5cab-40b6-97f3-6d19dd92a71f', NULL);

return v_status;
	
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.initvault() OWNER TO moss;

--
-- Name: markergameowners(character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION markergameowners(v_uuid character) RETURNS integer
    AS $$

/*
   This function is intended to look for anyone having a user-created
   marker game with this UUID.  If there are any references to the game
   it should obviously not be deleted.
 */

DECLARE
numrows integer;

BEGIN
  /* for user-created games the UUID is uuid_1 in the MarkerListNode */
  select count(child) from noderefs where parent = (
  SELECT nodeid FROM markergame where uuid_1 = v_uuid) into numrows;
  return numrows;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.markergameowners(v_uuid character) OWNER TO moss;

--
-- Name: newnodeid(integer); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION newnodeid(v_type integer) RETURNS numeric
    AS $$
/*
  Gets the next nodeid from the sequence and adds it to the master
  node table, and returns the nodeid to the caller.
*/

DECLARE
   v_nodeid numeric;

BEGIN

  if v_type is NULL then
    return 0;  /* have to have a type */
  end if;

  SELECT nextval('public.nodeid_seq') INTO v_nodeid;
  INSERT into nodes values (v_nodeid, v_type);

  return v_nodeid;
  
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.newnodeid(v_type integer) OWNER TO moss;

--
-- Name: newscore(numeric, text, integer, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION newscore(v_holder numeric, v_name text, v_type integer, v_score numeric, OUT v_id numeric, OUT v_createtime integer) RETURNS record
    AS $$

/*
   This function creates a new score of type described by v_name and v_type,
   held by v_holder, of initial value v_score.

   If the score already exists, returns v_id = 0. If the score type is not
    valid, returns v_id = 1. Otherwise returns the new score ID.
 */

DECLARE
  numrows integer;
  v_createtimecvt timestamp without time zone;
  typeok boolean;

BEGIN

  /* Check whether this score exists. */
  select count(*) into numrows from scores where holder=v_holder and name=v_name;
  if numrows != 0 then
    select 0, 0 into v_id, v_createtime;
    return;
  end if;

  /* Verify the score type is valid. */
  typeok := true;
  if v_type < 0 then
    typeok := false;
  end if;
  if v_type > 2 then
    typeok := false;
  end if;
  if not typeok then
    select 1, 0 into v_id, v_createtime;
    return;
  end if;

  /* Put it in the table. */
  insert into scores(holder, name, type, score) values(v_holder, v_name, v_type, v_score);

  select id, createtime from scores into v_id, v_createtimecvt where holder=v_holder and name=v_name;
  v_createtime := trunc(EXTRACT(EPOCH FROM v_createtimecvt));
  return;

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.newscore(v_holder numeric, v_name text, v_type integer, v_score numeric, OUT v_id numeric, OUT v_createtime integer) OWNER TO moss;

--
-- Name: notifyage(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION notifyage(v_nodeid numeric) RETURNS SETOF character
    AS $$
/*
  Algorithm:

  * get notifiers that correspond to age nodes, as long as v_nodeid isn't
    an ageinfo

  This is all that is needed because the ageinfo changes are handled by
  notifyplayers(). All age-specific stuff is in the age tree, and stuff that
  goes to player vaults is in the ageinfo tree, which does duplicate certain
  information, but keeps the two logically separated.
  Side note: the SDL has to be in the ageinfo tree, which is *why* when the
  "vault SDL" changes the server has to propagate the info to "age SDL" --
  those in the age but not owners won't get updates to the vault SDL.
*/
DECLARE
  ntype numeric;
BEGIN
  select type from nodes where nodeid=v_nodeid into ntype;
  if not FOUND or ntype = 33 then
    return;
  else
    return query select age.uuid_1 from age inner join noderefs on age.nodeid=noderefs.notifier where noderefs.child=v_nodeid or age.nodeid=v_nodeid group by age.uuid_1;
  end if;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.notifyage(v_nodeid numeric) OWNER TO moss;

--
-- Name: notifyplayers(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION notifyplayers(v_nodeid numeric) RETURNS SETOF numeric
    AS $$

/*
  Algorithm as follows (yuck):

  "get notifiers" means look up node refs with v_nodeid as the notifier or
  child itself (the latter test covers a change to the contents of the top
  node of each tree: player, ageinfo, system)

  * get notifiers for system tree; if not null, return all players (-1)
  * get notifiers that correspond to player nodes (KI numbers);
    if there are any, return them; this covers the personal vault because
    the notifier for that whole tree is the player nodeid
  * get notifiers that correspond to ageinfo nodes; if there is a change to
    that tree, tell all who have refs to the tree: AgeOwners and, alas,
    CanVisit as well
    * this is done by just getting these two playerinfo lists that are
      children of the ageinfo
    * these lists yield a set of playerinfo nodes, which contain the
      player ID (KI number)
    * get the set of those player IDs that are also connected and
      return them

  Note that the case of players in an age who are not owners or visitors is
  handled separately by notifyage().
*/

DECLARE
  v_node numeric;
  numrows integer;

BEGIN
  /* get notifiers for type system */
  select nodeid from system limit 1 into v_node;
  select count(notifier) into numrows from noderefs where child=v_nodeid and notifier=v_node;
  if v_node = v_nodeid or numrows > 0 then
    /* tell all players; any further computation is irrelevant */
    v_node = -1;
    return query select v_node;
  else
    /* um, wow, can this really be right? (don't ask how efficient it is) */
    return query (select id from connected inner join noderefs on connected.id=noderefs.notifier where noderefs.child=v_nodeid or noderefs.notifier=v_nodeid UNION select playerinfo.ki from nodes inner join noderefs nr on nodes.nodeid=nr.notifier inner join noderefs nro on nodes.nodeid=nro.parent inner join playerinfolist on nro.child=playerinfolist.nodeid inner join noderefs nrn on nrn.parent=playerinfolist.nodeid inner join playerinfo on nrn.child=playerinfo.nodeid inner join connected on playerinfo.ki=connected.id where nodes.type = 33 and (nr.child=v_nodeid or nr.notifier=v_nodeid) and playerinfolist.type in (18, 19));
  end if;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.notifyplayers(v_nodeid numeric) OWNER TO moss;

--
-- Name: removenode(numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION removenode(v_parent numeric, v_child numeric) RETURNS integer
    AS $$

DECLARE
  numrows integer;
  numparents integer;
  numchildren integer;
  v_ageinfo numeric;

begin
/* (5:08:55 AM) a'moaca': You know what would be cool, would be if removenode()
   would delete actual nodes when the last ref to them is removed.


  (12:20:06 AM) a'moaca': But it doesn't clean up, say, when an age is deleted via
   a book on the shelf, since there is a whole tree of nodes for that age. Actually,
   I don't know what refs are deleted for that; possibly none of those actually have
   a tree under them anyway, in which case the DB would have to notice it's an ageish
   node, go find the root of the tree, etc.

  check when it deletes a PlayerInfo -> AgeOwnersFolder noderef, and delete the age if
  there are no other owners.

*/

  /* see how many refs we have, so we can return the count to the caller */
  select count(parent) from noderefs where parent = v_parent and child = v_child into numrows;

  if numrows = 0 then
    return numrows;
  end if;

  /* check to see if the child is an agelink.  If it is, we can try to delete the age - deleteage()
     checks for owners and visitors, so will not delete the age if there are either. */
  if (select type from nodes where nodeid = v_child) = 28 then
    select child from noderefs where parent = v_child into v_ageinfo;
    /* delete the noderef */
    delete from noderefs where parent = v_parent and child = v_child;
    if v_ageinfo is not NULL then
      delete from noderefs where parent = v_child and child = v_ageinfo; -- I think the client should do this, but it does not.
      perform deleteage(v_ageinfo);
      /* input child node has how many child nodes? */
      select count(parent) from noderefs where parent = v_child into numchildren;
      /* input child node has how many many parent nodes? */
      select count(child) from noderefs where child = v_child into numparents;
      /*  delete node if it is has no parents and no children */
      if ((numchildren = 0) and (numparents = 0)) then
        delete from nodes where nodeid = v_child;
      end if;
    else
      /* ageinfo is null - agelink is for a child age already deleted */
      /* delete the noderef */
      delete from noderefs where parent = v_parent and child = v_child;
      /* input child node has how many child nodes? */
      select count(parent) from noderefs where parent = v_child into numchildren;
      /* input child node has how many many parent nodes? */
      select count(child) from noderefs where child = v_child into numparents;
      /*  delete node if it is has no parents and no children */
      if ((numchildren = 0) and (numparents = 0)) then
        delete from nodes where nodeid = v_child;
      end if;      
    end if;
  else  
    /* delete the noderef */
    delete from noderefs where parent = v_parent and child = v_child;
    /* input child node has how many child nodes? */
    select count(parent) from noderefs where parent = v_child into numchildren;
    /* input child node has how many many parent nodes? */
    select count(child) from noderefs where child = v_child into numparents;
    /*  delete node if it is has no parents and no children */
    if ((numchildren = 0) and (numparents = 0)) then
      /* check to see if the child is a marker game */
      if (select type from nodes where nodeid = v_child) = 35 then
        /* delete the marker game */
        delete from markertemplates where uuid = (select uuid_1 from markergame where nodeid = v_child);
      end if;
      delete from nodes where nodeid = v_child;
    end if;
  end if;
  return numrows;
	
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.removenode(v_parent numeric, v_child numeric) OWNER TO moss;

--
-- Name: renamemarker(numeric, numeric, character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION renamemarker(v_gameid numeric, v_id numeric, v_newname character) RETURNS integer
    AS $$

/* returns 0 on success, 1 if marker does not exist */

DECLARE
numrows integer;

BEGIN
  select count(*) into numrows from markers where game_id = v_gameid and marker_number = v_id;
  if numrows = 0 then
    return 1;
  end if;
  update markers set marker_name = v_newname where game_id = v_gameid and marker_number = v_id;
  return 0;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.renamemarker(v_gameid numeric, v_id numeric, v_newname character) OWNER TO moss;

--
-- Name: renamemarkergame(numeric, character); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION renamemarkergame(v_gameid numeric, v_newname character) RETURNS integer
    AS $$

/* returns 0 on success, 1 if game does not exist */

DECLARE
numrows integer;

BEGIN
  select count(*) into numrows from markertemplates where game_id = v_gameid;
  if numrows = 0 then
    return 1;
  end if;
  update markertemplates set name = v_newname where game_id = v_gameid;
  return 0;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.renamemarkergame(v_gameid numeric, v_newname character) OWNER TO moss;

--
-- Name: sendnode(numeric, numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION sendnode(v_player numeric, v_nodeid numeric, v_sender numeric, OUT v_result integer, OUT v_inbox numeric) RETURNS record
    AS $$

/*
   This is for kCli2Auth_VaultSendNode 0x23
   v_player = player node of recipient (KI number)
   v_nodeid = node to send
   v_sender = player node of sender (KI number)

   Returns same result codes as addnode():
   0 = success
   1 = noderef already exists
   2 = node not found

   Client does not get a return packet, so log errors to
   MOSS log if we care.    

*/

begin

select child from noderefs nr inner join folder f on f.nodeid = nr.child where nr.parent = v_player and f.type = 1 limit 1 into v_inbox;
select addnode(v_inbox, v_nodeid, v_sender) into v_result;
return;

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.sendnode(v_player numeric, v_nodeid numeric, v_sender numeric, OUT v_result integer, OUT v_inbox numeric) OWNER TO moss;

--
-- Name: setmarkerto(numeric, numeric, numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION setmarkerto(v_gameid numeric, v_player numeric, v_id numeric, v_value numeric) RETURNS integer
    AS $$
/*
    XXX It would be much easier on the DB if updates to markers are batched by
    the game server. The difficulty is in keeping synchronized when the client
    departs a given game server, making sure that the game is updated before
    it is read in the new age. This can be done, but both the batching and
    synchronization are more difficult than the simplest possible solution.	
    If/when batching is done the markersinplay table could be changed to store
    a blob for a bitmask perhaps (though in capture/hold games it may require
    more than one bit per marker).

    But for now, one row per marker. Expensive for large games, but basic
    functionality is the goal at this stage.

    Returns 1 if the marker already had that value, -1 if the marker
    doesn't exist, 0 otherwise.
*/

DECLARE
numrows integer;
old_value numeric;

BEGIN
  /* first see if marker exists in markers table */
  select count(*) into numrows from markers where game_id = v_gameid and marker_number = v_id;
  if numrows = 0 then
    /* the marker doesn't exist so just ignore it */
    return -1;
  end if;

  /* see if the marker is in the markersinplay table */
  select count(*) into numrows from markersinplay where game_id = v_gameid and player = v_player and marker_number = v_id; 
  if numrows = 0 then
    /* marker not already in table, so add it */
    insert into markersinplay values(v_gameid, v_player, v_id, v_value);
    return 0;
  end if;

  /* see if the old value is different than new */
  select value into old_value from markersinplay where game_id = v_gameid and player = v_player and marker_number = v_id;
  if old_value = v_value then
    return 1;
  end if;
  update markersinplay set value = v_value where game_id = v_gameid and player = v_player and marker_number = v_id;
  return 0;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.setmarkerto(v_gameid numeric, v_player numeric, v_id numeric, v_value numeric) OWNER TO moss;

--
-- Name: setplayerconnected(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION setplayerconnected(v_ki numeric) RETURNS void
    AS $$

BEGIN
  if (select count(*) from connected where id = v_ki) < 1 then
    insert into connected values(v_ki);
  end if;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.setplayerconnected(v_ki numeric) OWNER TO moss;

--
-- Name: setplayeroffline(numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION setplayeroffline(v_ki numeric, OUT v_online numeric, OUT v_node numeric) RETURNS record
    AS $$

BEGIN
  delete from connected where id = v_ki;
  select online,nodeid from playerinfo where ki = v_ki limit 1 into v_online,v_node;
  update playerinfo set online = 0, uuid_1 = '00000000-0000-0000-0000-000000000000', string64_1 = '' where ki = v_ki;
  return;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.setplayeroffline(v_ki numeric, OUT v_online numeric, OUT v_node numeric) OWNER TO moss;

--
-- Name: stalerefs(); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION stalerefs() RETURNS void
    AS $$

/* Find noderefs which refer to nodes which do not exist.
   Output will be in log file, or in messages tab if running
   from pgAdmin. */

declare
v_noderefs noderefs;

begin

for v_noderefs in select * from noderefs
loop
  if (select count(nodeid) from nodes where nodeid = v_noderefs.parent) < 1
    then RAISE NOTICE 'Stale noderef.  Node %.', v_noderefs.parent;
  end if;

  if (select count(nodeid) from nodes where nodeid = v_noderefs.child) < 1
    then RAISE NOTICE 'Stale noderef.  Node %.', v_noderefs.child;
  end if;

end loop;

return;

END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.stalerefs() OWNER TO moss;

--
-- Name: startmarkergame(numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION startmarkergame(v_gameid numeric, v_player numeric) RETURNS integer
    AS $$
/*
    XXX see setmarkerto() comment -- if batching is done this function might
    be nonempty
    XXX this function also might be nonempty if deletions and additions for
    user-created marker games are propagated to other players; we would need
    to know who is playing what games to do that
    XXX this function also should be nonempty if we need to keep track of
    accumulated play time, which needs to be persistent across game servers
    and logins
*/
BEGIN
  return 0;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.startmarkergame(v_gameid numeric, v_player numeric) OWNER TO moss;

--
-- Name: stopmarkergame(numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION stopmarkergame(v_gameid numeric, v_player numeric) RETURNS void
    AS $$

BEGIN
  delete from markersinplay where game_id = v_gameid and player = v_player;
END
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.stopmarkergame(v_gameid numeric, v_player numeric) OWNER TO moss;

--
-- Name: transferscore(numeric, numeric, numeric); Type: FUNCTION; Schema: public; Owner: moss
--

CREATE FUNCTION transferscore(v_id numeric, v_dest numeric, v_value numeric) RETURNS integer
    AS $$

/* 
   This function adds a value (which may be negative) to the score. If
   the score type does not allow adding negative points, or adding points
   at all, no change is made and an error is returned.

   0 = success
   1 = negative addition not allowed, or score is fixed
   2 = score not found
   3 = score does not have as many points as transfer requests
*/

DECLARE
  numrows integer;
  scoretype integer;
  scoreval numeric;

BEGIN
  /* Check that these scores exist. */
  select count(*) into numrows from scores where id=v_id;
  if numrows = 0 then
    return 1; /* score does not exist */
  end if;
  select count(*) into numrows from scores where id=v_dest;
  if numrows = 0 then
    return 1; /* score does not exist */
  end if;

  /* Check score type and data. */
  select type into scoretype from scores where id=v_dest;
  if v_value < 0 then
    if scoretype != 2 then /* 2 == kAccumAllowNegative */
      return 2;
    end if;
  end if;
  if scoretype = 0 then /* 0 == kFixed */
    return 2;
  end if;
  select type, score into scoretype, scoreval from scores where id=v_id;
  if v_value < 0 then
    if scoretype != 2 then /* 2 == kAccumAllowNegative */
      return 2;
    end if;
  end if;
  if scoretype = 0 then /* 0 == kFixed */
    return 2;
  end if;

  if abs(scoreval) < abs(v_value) then
    return 3;
  end if;
  if scoreval < 0 and v_value > 0 then
    return 3;
  end if;
  if scoreval > 0 and v_value < 0 then
    return 3;
  end if;

  /* Do the change. */
  scoreval := scoreval - v_value;
  update scores set score=scoreval where id=v_id;
  select score into scoreval from scores where id=v_dest;
  scoreval := scoreval + v_value;
  update scores set score=scoreval where id=v_dest;
  return 0;
END;
$$
    LANGUAGE plpgsql;


ALTER FUNCTION public.transferscore(v_id numeric, v_dest numeric, v_value numeric) OWNER TO moss;

--
-- Data for Name: accounts; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY accounts (name, email, hash, id, class, visitor, banned) FROM stdin;
\.


--
-- Data for Name: admin; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY admin (name, createtime, modifytime, uuid_1) FROM stdin;
mossadmin	2008-06-08 02:51:47.753116	2008-06-08 02:51:47.753116	8428b096-45fe-400a-8a09-6e0dfd9f261a
\.


--
-- Data for Name: age; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY age (nodeid, createtime, modifytime, creatoracctid, creatorid, uuid_1, uuid_2, filename) FROM stdin;
\.


--
-- Data for Name: ageinfo; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY ageinfo (nodeid, createtime, modifytime, creatoracctid, creatorid, int32_1, int32_2, int32_3, uint32_1, uint32_2, uint32_3, uuid_1, uuid_2, string64_2, string64_3, string64_4, text_1) FROM stdin;
\.


--
-- Data for Name: ageinfolist; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY ageinfolist (nodeid, createtime, modifytime, creatoracctid, creatorid, type) FROM stdin;
\.


--
-- Data for Name: agelink; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY agelink (nodeid, createtime, modifytime, createageuuid, createagename, creatoracctid, creatorid, shared, volatile, linkpoints) FROM stdin;
\.


--
-- Data for Name: ccr; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY ccr (nodeid) FROM stdin;
\.


--
-- Data for Name: chronicle; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY chronicle (nodeid, createtime, modifytime, createageuuid, createagename, creatoracctid, creatorid, type, name, value) FROM stdin;
\.


--
-- Data for Name: connected; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY connected (id) FROM stdin;
\.


--
-- Data for Name: folder; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY folder (nodeid, createtime, modifytime, createageuuid, createagename, creatoracctid, creatorid, type, name) FROM stdin;
\.


--
-- Data for Name: gameserver; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY gameserver (nodeid) FROM stdin;
\.


--
-- Data for Name: image; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY image (nodeid, createtime, modifytime, createageuuid, createagename, creatoracctid, creatorid, "exists", name, image) FROM stdin;
\.


--
-- Data for Name: markergame; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY markergame (nodeid, createtime, modifytime, createageuuid, createagename, creatoracctid, creatorid, name, uuid_1) FROM stdin;
\.


--
-- Data for Name: markers; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY markers (game_id, x, y, z, marker_number, marker_name, age_name) FROM stdin;
\.


--
-- Data for Name: markersinplay; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY markersinplay (game_id, player, marker_number, value) FROM stdin;
\.


--
-- Data for Name: markertemplates; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY markertemplates (game_id, uuid, owner, type, name, next_number) FROM stdin;
\.


--
-- Data for Name: noderefs; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY noderefs (parent, child, ownerid, notifier) FROM stdin;
\.


--
-- Data for Name: nodes; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY nodes (nodeid, type) FROM stdin;
\.


--
-- Data for Name: player; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY player (nodeid, createtime, modifytime, creatoracctid, creatorid, int32_1, int32_2, uint32_1, uuid_1, uuid_2, gender, name) FROM stdin;
\.


--
-- Data for Name: playerinfo; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY playerinfo (nodeid, createtime, modifytime, creatoracctid, creatorid, online, ki, uuid_1, string64_1, name) FROM stdin;
\.


--
-- Data for Name: playerinfolist; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY playerinfolist (nodeid, createtime, modifytime, creatoracctid, creatorid, type) FROM stdin;
\.


--
-- Data for Name: scores; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY scores (holder, name, id, createtime, type, score) FROM stdin;
\.


--
-- Data for Name: sdl; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY sdl (nodeid, createtime, modifytime, createageuuid, createagename, creatoracctid, creatorid, int32_1, name, blob) FROM stdin;
\.


--
-- Data for Name: server; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY server (nodeid) FROM stdin;
\.


--
-- Data for Name: system; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY system (nodeid, createtime, modifytime, creatoracctid, creatorid) FROM stdin;
\.


--
-- Data for Name: textnote; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY textnote (nodeid, createtime, modifytime, createageuuid, createagename, creatoracctid, creatorid, int32_1, int32_2, title, value) FROM stdin;
\.


--
-- Data for Name: userdefined; Type: TABLE DATA; Schema: public; Owner: moss
--

COPY userdefined (nodeid) FROM stdin;
\.


--
-- Name: accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (name);


--
-- Name: admin_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY admin
    ADD CONSTRAINT admin_pkey PRIMARY KEY (name);


--
-- Name: age_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY age
    ADD CONSTRAINT age_pkey PRIMARY KEY (nodeid);


--
-- Name: ageinfo_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY ageinfo
    ADD CONSTRAINT ageinfo_pkey PRIMARY KEY (nodeid);


--
-- Name: ageinfolist_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY ageinfolist
    ADD CONSTRAINT ageinfolist_pkey PRIMARY KEY (nodeid);


--
-- Name: agelink_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY agelink
    ADD CONSTRAINT agelink_pkey PRIMARY KEY (nodeid);


--
-- Name: ccr_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY ccr
    ADD CONSTRAINT ccr_pkey PRIMARY KEY (nodeid);


--
-- Name: chronicle_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY chronicle
    ADD CONSTRAINT chronicle_pkey PRIMARY KEY (nodeid);


--
-- Name: folder_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY folder
    ADD CONSTRAINT folder_pkey PRIMARY KEY (nodeid);


--
-- Name: gameserver_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY gameserver
    ADD CONSTRAINT gameserver_pkey PRIMARY KEY (nodeid);


--
-- Name: image_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY image
    ADD CONSTRAINT image_pkey PRIMARY KEY (nodeid);


--
-- Name: markergame_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY markergame
    ADD CONSTRAINT markergame_pkey PRIMARY KEY (nodeid);


--
-- Name: markers_game_id; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY markers
    ADD CONSTRAINT markers_game_id PRIMARY KEY (game_id, marker_number);


--
-- Name: markersinplay_game_id-marker_number; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY markersinplay
    ADD CONSTRAINT "markersinplay_game_id-marker_number" PRIMARY KEY (game_id, marker_number);


--
-- Name: markertemplates_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY markertemplates
    ADD CONSTRAINT markertemplates_pkey PRIMARY KEY (game_id);


--
-- Name: nodeid; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY nodes
    ADD CONSTRAINT nodeid PRIMARY KEY (nodeid);


--
-- Name: noderefs_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY noderefs
    ADD CONSTRAINT noderefs_pkey PRIMARY KEY (parent, child);


--
-- Name: player_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY player
    ADD CONSTRAINT player_pkey PRIMARY KEY (nodeid);


--
-- Name: playerinfo_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY playerinfo
    ADD CONSTRAINT playerinfo_pkey PRIMARY KEY (nodeid);


--
-- Name: playerinfolist_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY playerinfolist
    ADD CONSTRAINT playerinfolist_pkey PRIMARY KEY (nodeid);


--
-- Name: scores_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY scores
    ADD CONSTRAINT scores_pkey PRIMARY KEY (id);


--
-- Name: sdl_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY sdl
    ADD CONSTRAINT sdl_pkey PRIMARY KEY (nodeid);


--
-- Name: server_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY server
    ADD CONSTRAINT server_pkey PRIMARY KEY (nodeid);


--
-- Name: system_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY system
    ADD CONSTRAINT system_pkey PRIMARY KEY (nodeid);


--
-- Name: textnote_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY textnote
    ADD CONSTRAINT textnote_pkey PRIMARY KEY (nodeid);


--
-- Name: userdefined_pkey; Type: CONSTRAINT; Schema: public; Owner: moss; Tablespace: 
--

ALTER TABLE ONLY userdefined
    ADD CONSTRAINT userdefined_pkey PRIMARY KEY (nodeid);


--
-- Name: noderefs_idx; Type: INDEX; Schema: public; Owner: moss; Tablespace: 
--

CREATE INDEX noderefs_idx ON noderefs USING btree (parent, child, ownerid);


--
-- Name: nodes_idx; Type: INDEX; Schema: public; Owner: moss; Tablespace: 
--

CREATE INDEX nodes_idx ON nodes USING btree (nodeid, type);


--
-- Name: age_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY age
    ADD CONSTRAINT age_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: ageinfo_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY ageinfo
    ADD CONSTRAINT ageinfo_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: ageinfolist_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY ageinfolist
    ADD CONSTRAINT ageinfolist_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: agelink_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY agelink
    ADD CONSTRAINT agelink_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: chronicle_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY chronicle
    ADD CONSTRAINT chronicle_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: folder_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY folder
    ADD CONSTRAINT folder_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: image_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY image
    ADD CONSTRAINT image_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: markergame_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY markergame
    ADD CONSTRAINT markergame_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: markers_game_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY markers
    ADD CONSTRAINT markers_game_id_fkey FOREIGN KEY (game_id) REFERENCES markertemplates(game_id) ON DELETE CASCADE;


--
-- Name: markersinplay_game_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY markersinplay
    ADD CONSTRAINT markersinplay_game_id_fkey FOREIGN KEY (game_id, marker_number) REFERENCES markers(game_id, marker_number) ON DELETE CASCADE;


--
-- Name: player_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY player
    ADD CONSTRAINT player_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: playerinfo_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY playerinfo
    ADD CONSTRAINT playerinfo_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: playerinfolist_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY playerinfolist
    ADD CONSTRAINT playerinfolist_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: sdl_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY sdl
    ADD CONSTRAINT sdl_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: system_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY system
    ADD CONSTRAINT system_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: textnote_fkey; Type: FK CONSTRAINT; Schema: public; Owner: moss
--

ALTER TABLE ONLY textnote
    ADD CONSTRAINT textnote_fkey FOREIGN KEY (nodeid) REFERENCES nodes(nodeid) ON DELETE CASCADE;


--
-- Name: public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

