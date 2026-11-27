-- SQLITE-SPECIFIC: append-only guard for change_history.
-- The PostgreSQL variant replaces this file with a trigger function + BEFORE UPDATE OR DELETE trigger.
CREATE TRIGGER change_history_no_update BEFORE UPDATE ON change_history
BEGIN SELECT RAISE(ABORT, 'change_history is append-only'); END;
CREATE TRIGGER change_history_no_delete BEFORE DELETE ON change_history
BEGIN SELECT RAISE(ABORT, 'change_history is append-only'); END;
