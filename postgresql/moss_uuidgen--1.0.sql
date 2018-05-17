CREATE OR REPLACE FUNCTION uuid() RETURNS text
    AS 'moss_uuidgen', 'moss_uuidgen_text'
    LANGUAGE c STRICT; 
