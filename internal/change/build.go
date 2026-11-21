package change

import "time"

// Change types.
const (
	TypeEntityCreated       = "entityCreated"
	TypePropertyChanged     = "propertyChanged"
	TypeRelationshipCreated = "relationshipCreated"
	// TypeVulnerabilityMerged: an advisory-keyed Vulnerability was merged into
	// the Vulnerability of its single CVE alias (Requirement 9.7). EntityKey is
	// the surviving key, OldValue the JSON list of both prior keys, NewValue
	// the JSON string of the surviving key.
	TypeVulnerabilityMerged = "vulnerabilityMerged"
	// TypeAliasConflict: an advisory names two or more CVE ids; it was attached
	// to each and nothing was merged (Requirement 9.9). EntityKey is the
	// advisory-keyed Vulnerability key, NewValue the JSON list of the CVE ids.
	TypeAliasConflict = "aliasConflict"
)

// Builder fills the fields shared by every record of one run.
type Builder struct {
	Source string
	RunID  string
	At     time.Time
}

func (b Builder) rec(key, typ, field, oldV, newV string) Record {
	return Record{EntityKey: key, Type: typ, Field: field, OldValue: oldV, NewValue: newV,
		Source: b.Source, RunID: b.RunID, At: b.At}
}

// EntityCreated records the creation of an entity with its properties.
func (b Builder) EntityCreated(key string, props map[string]any) Record {
	return b.rec(key, TypeEntityCreated, "", "", EncodeProps(props))
}

// RelationshipCreated records the creation of a relationship.
func (b Builder) RelationshipCreated(key string, props map[string]any) Record {
	return b.rec(key, TypeRelationshipCreated, "", "", EncodeProps(props))
}

// PropertyChanged records a property change; a nil newV records removal.
func (b Builder) PropertyChanged(key, field string, oldV, newV any) Record {
	return b.rec(key, TypePropertyChanged, field, EncodeValue(oldV), EncodeValue(newV))
}
