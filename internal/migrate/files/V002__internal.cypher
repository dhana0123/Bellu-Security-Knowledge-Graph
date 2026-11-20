CREATE CONSTRAINT bskg_checkpoint_source IF NOT EXISTS FOR (n:Checkpoint) REQUIRE n.source IS UNIQUE
;
CREATE CONSTRAINT bskg_lock_source IF NOT EXISTS FOR (n:Lock) REQUIRE n.source IS UNIQUE
;
CREATE CONSTRAINT bskg_syncrun_id IF NOT EXISTS FOR (n:SyncRun) REQUIRE n.id IS UNIQUE
;
CREATE CONSTRAINT bskg_job_name IF NOT EXISTS FOR (n:Job) REQUIRE n.name IS UNIQUE
;
CREATE CONSTRAINT bskg_buildmeta_id IF NOT EXISTS FOR (n:BuildMeta) REQUIRE n.id IS UNIQUE
;
CREATE CONSTRAINT bskg_deadletter_id IF NOT EXISTS FOR (n:DeadLetter) REQUIRE n.id IS UNIQUE
;
CREATE CONSTRAINT bskg_change_id IF NOT EXISTS FOR (n:Change) REQUIRE n.id IS UNIQUE
;
CREATE CONSTRAINT bskg_apikey_id IF NOT EXISTS FOR (n:ApiKey) REQUIRE n.id IS UNIQUE
;
CREATE CONSTRAINT bskg_apikey_name IF NOT EXISTS FOR (n:ApiKey) REQUIRE n.name IS UNIQUE
;
CREATE INDEX bskg_change_entitykey IF NOT EXISTS FOR (n:Change) ON (n.entityKey)
;
CREATE INDEX bskg_change_at IF NOT EXISTS FOR (n:Change) ON (n.at)
;
CREATE INDEX bskg_syncrun_source IF NOT EXISTS FOR (n:SyncRun) ON (n.source)
;
CREATE INDEX bskg_deadletter_source IF NOT EXISTS FOR (n:DeadLetter) ON (n.source)
