
/* This is to introduce the new VIEWMYNOTES permission level.
/* We add an extra bit in the 4th place from the right, and shift the other bits up */
update staff_member
set permissions = CONV(concat(left(bin(permissions), length(bin(permissions))-4),"1",right(bin(permissions),4)), 2, 10)
where permissions <> 2147483647
AND permissions & 16 = 16;

update staff_member
set permissions = CONV(concat(left(bin(permissions), length(bin(permissions))-4),"0",right(bin(permissions),4)), 2, 10)
where permissions <> 2147483647
AND permissions & 16 = 0;

ALTER TABLE abstract_note
MODIFY COLUMN creator INT(11) DEFAULT NULL;

UPDATE abstract_note
SET creator = NULL where creator = 0;

update abstract_note set assignee = null where assignee = 0;

/* Introduce a new view to filter the visible notes */
CREATE TABLE `_abstract_note` (
 `id` int(11) NOT NULL AUTO_INCREMENT,
 `subject` varchar(255) NOT NULL DEFAULT '',
 `details` text NOT NULL,
 `status` varchar(255) NOT NULL DEFAULT 'no_action',
 `status_last_changed` datetime DEFAULT NULL,
 `assignee` int(11) DEFAULT NULL,
 `assignee_last_changed` datetime DEFAULT NULL,
 `action_date` date NOT NULL,
 `creator` int(11) DEFAULT NULL,
 `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
 `editor` int(11) DEFAULT NULL,
 `edited` datetime DEFAULT NULL,
 `history` text NOT NULL,
 PRIMARY KEY (`id`)
) ENGINE=InnoDB;

ALTER TABLE _abstract_note ADD CONSTRAINT FOREIGN KEY (`assignee`) REFERENCES `_person`(`id`) ON DELETE RESTRICT;
ALTER TABLE _abstract_note ADD CONSTRAINT FOREIGN KEY (`creator`) REFERENCES `_person`(`id`) ON DELETE RESTRICT;
ALTER TABLE _abstract_note ADD CONSTRAINT FOREIGN KEY (`editor`) REFERENCES `_person`(`id`) ON DELETE RESTRICT;

INSERT INTO _abstract_note
(id, subject, details, status, status_last_changed, assignee, assignee_last_changed, action_date, creator, created, editor, edited, history)
SELECT id, subject, details, status, status_last_changed, assignee, assignee_last_changed, action_date, creator, created, editor, edited, history FROM abstract_note;

ALTER TABLE abstract_note RENAME TO _abstract_note_old_backup;

create view abstract_note as
select an.* from _abstract_note an
WHERE ((an.assignee = getCurrentUserID() AND an.status = 'pending') OR (48 = (SELECT permissions & 48 FROM staff_member WHERE id = getCurrentUserID())));