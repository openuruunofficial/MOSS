---
---  Replace MOSS welcome note text with MOUL Laxman welcome note text
---

update textnote set value = E'Dear Visitors and Explorers:\r\n\r\nIf you are just arriving for the first time, welcome to the Cavern!\r\n\r\nIf you are returning to the Cavern, we apologize for the inconvenience that required you to obtain a new KI.  It seems that all of the KIs that were in use before that bizarre scream occurred have been permanently disabled.  Fortunately, it seems that the lattice was not damaged.\r\n\r\nThere have also been many reports of subtle changes that apparently occurred at the same time as that scream, so, as a precaution, we have closed down the most unstable portions of the city to verify that those areas have not been adversely affected.  We will be re-opening portions of the city as soon as we can.\r\n\r\nThank you for your patience and understanding.\r\n\r\nVictor Laxman'
where title = 'Welcome' and creatorid = '0';
