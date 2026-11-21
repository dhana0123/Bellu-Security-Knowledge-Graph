# Graph model

BSKG uses the VulKG graph model (https://github.com/happyResearcher/VulKG,
DOI 10.1145/3671005) as its schema. Labels, relationship types, key
properties, and property names follow VulKG. Migration `V001` creates the
constraints and indexes, `V002` the bookkeeping constraints.

## Deviations from VulKG

- CVSS score properties are stored as decimals. VulKG casts several to
  integers.
- No range index on `Vulnerability.description`. A full-text index
  (`VulnerabilityDescriptionFullTextSchema`) serves text search.
- Empty source fields leave a property absent instead of storing an empty
  string.
- Provenance is stored as `p_<source>_run`, `p_<source>_at`, `p_<source>_ref`,
  and `sources` on nodes and relationships. Relationships carry a derived
  `removed` flag when every source dropped them.

The complete label and relationship table is in the design document
(`internal/model`, task 5.1).
