-- MOSS - A server for the Myst Online: Uru Live client/protocol
-- Copyright (C) 2009  cjkelly1 and a'moaca'
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
--  along with this program.  If not, see <http://www.gnu.org/licenses/>.


drop table if exists namelookup;
CREATE TABLE namelookup (
  type integer,
  name varchar(20)
 );
insert into namelookup values(3,'age'); 
insert into namelookup values(33,'ageinfo');
insert into namelookup values(34,'ageinfolist');
insert into namelookup values(28,'agelink');
insert into namelookup values(29,'chronicle');
insert into namelookup values(22,'folder');
insert into namelookup values(25,'image');
insert into namelookup values(35,'markergame');
insert into namelookup values(2,'player');
insert into namelookup values(23,'playerinfo');
insert into namelookup values(30,'playerinfolist');
insert into namelookup values(27,'SDL');
insert into namelookup values(24,'system');
insert into namelookup values(26,'textnote');

drop table if exists folderlookup;
CREATE TABLE folderlookup (
  type integer,
  name varchar(30)
 );
insert into folderlookup values(0,'Generic');
insert into folderlookup values(1,'InboxFolder');
insert into folderlookup values(2,'BuddyListFolder');
insert into folderlookup values(3,'IgnoreListFolder');
insert into folderlookup values(4,'PeopleIKnowAboutFolder');
insert into folderlookup values(5,'VaultMgrGlobalDataFolder');
insert into folderlookup values(6,'ChronicleFolder');
insert into folderlookup values(7,'AvatarOutfitFolder');
insert into folderlookup values(8,'AgeTypeJournalFolder');
insert into folderlookup values(9,'SubAgesFolder');
insert into folderlookup values(10,'DeviceInboxFolder');
insert into folderlookup values(11,'HoodMembersFolder');
insert into folderlookup values(12,'AllPlayersFolder');
insert into folderlookup values(13,'AgeMembersFolder');
insert into folderlookup values(14,'AgeJournalsFolder');
insert into folderlookup values(15,'AgeDevicesFolder');
insert into folderlookup values(16,'AgeInstaceSDLNode');
insert into folderlookup values(17,'AgeGlobalSDLNode');
insert into folderlookup values(18,'CanVisitFolder');
insert into folderlookup values(19,'AgeOwnersFolder');
insert into folderlookup values(20,'AllAgeGlobalSDLNodesFolder');
insert into folderlookup values(21,'PlayerInfoNodeFolder');
insert into folderlookup values(22,'PublicAgesFolder');
insert into folderlookup values(23,'AgesIOwnFolder');
insert into folderlookup values(24,'AgesICanVisitFolder');
insert into folderlookup values(25,'AvatarClosetFolder');
insert into folderlookup values(26,'AgeInfoNodeFolder');
insert into folderlookup values(27,'SystemNode');
insert into folderlookup values(28,'PlayerInviteFolder');
insert into folderlookup values(29,'CCRPlayersFolder');
insert into folderlookup values(30,'GlobalInboxFolder');
insert into folderlookup values(31,'ChildAgesFolder');
insert into folderlookup values(32,'GameScoresFolder');

drop function if exists reftree(v_nodeid numeric, OUT parent numeric, OUT parent_type text, OUT child numeric, OUT child_type text, OUT folder_type text, OUT owner numeric, OUT notifier numeric);

CREATE FUNCTION reftree(v_nodeid numeric, OUT parent numeric, OUT parent_type text, OUT child numeric, OUT child_type text, OUT folder_type text, OUT owner numeric, OUT notifier numeric) RETURNS SETOF record
    AS $$

/* This function fetches a list of node refs */

DECLARE
v_noderefs record;
v_type numeric;

BEGIN

for v_noderefs in
      select nr.parent,tn1.name,nr.child,nr.ownerid,nr.notifier from noderefs nr
	inner join nodes n1 on nr.parent = n1.nodeid
	inner join nodes n2 on nr.child = n2.nodeid
	inner join namelookup tn1 on n1.type = tn1.type
	where nr.parent = v_nodeid order by nr.parent
      loop
        parent = v_noderefs.parent;
	parent_type = v_noderefs.name;
	child = v_noderefs.child;
	owner = v_noderefs.ownerid;
	notifier = v_noderefs.notifier;
	select type from nodes where nodeid = child into v_type;
	select name from namelookup where type = v_type into child_type;
	folder_type = '';
	if v_type = 22 then
	  select type from folder where nodeid = child into v_type;
	  select name from folderlookup where type = v_type into folder_type;
	else
	  if v_type = 34 then
	    select type from ageinfolist where nodeid = child into v_type;
	    select name from folderlookup where type = v_type into folder_type;
	  else
	    if v_type = 30 then
	      select type from playerinfolist where nodeid = child into v_type;
	      select name from folderlookup where type = v_type into folder_type;
	    end if;
	  end if;
	end if;
        return next;
        for v_noderefs in
              select * from reftree(v_noderefs.child)
        loop
	      parent = v_noderefs.parent;
	      parent_type = v_noderefs.parent_type;
	      child = v_noderefs.child;
	      owner = v_noderefs.owner;
	      notifier = v_noderefs.notifier;
	      child_type = v_noderefs.child_type;
	      folder_type = v_noderefs.folder_type;
              return next;
        end loop;
      end loop;
return;
/*
for v_noderefs in
      select nr.parent,tn1.name,nr.child,tn2.name,0,nr.ownerid from noderefs nr
	inner join nodes n1 on nr.parent = n1.nodeid
	inner join nodes n2 on nr.child = n2.nodeid
	inner join namelookup tn1 on n1.type = tn1.type
	inner join namelookup tn2 on n2.type = tn2.type
	where nr.parent = v_nodeid order by nr.parent
      loop
        return next;
        for v_noderefs in
              select * from reftree(v_noderefs.child)
        loop
              return next;
        end loop;
      end loop;
return;
*/
END;
$$
    LANGUAGE plpgsql;

ALTER FUNCTION public.reftree(v_nodeid numeric, OUT parent numeric, OUT parent_type text, OUT child numeric, OUT child_type text, OUT folder_type text, OUT owner numeric, OUT notifier numeric) OWNER TO moss;
