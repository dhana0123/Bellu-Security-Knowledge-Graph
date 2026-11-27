-- SQLITE-SPECIFIC: append-only guard for intel_change.
CREATE TRIGGER intel_change_no_update BEFORE UPDATE ON intel_change
BEGIN SELECT RAISE(ABORT, 'intel_change is append-only'); END;
CREATE TRIGGER intel_change_no_delete BEFORE DELETE ON intel_change
BEGIN SELECT RAISE(ABORT, 'intel_change is append-only'); END;
