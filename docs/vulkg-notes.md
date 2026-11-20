# VulKG notes

Upstream: https://github.com/happyResearcher/VulKG

## File-name mismatch

Two import files are named with the typo `Vulnerabiliy_` in the repository, but
the deployment script loads the `Vulnerability_` names:

| Repository name | Script name |
| --- | --- |
| `Vulnerabiliy_HAS_EXPLOIT_Exploit_relationship.csv` | `Vulnerability_HAS_EXPLOIT_Exploit_relationship.csv` |
| `DomainNodes_Vulnerabiliy_HAS_REFERENCE_Domain_relationship.csv` | `DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv` |

The manifest keeps both names. The S3 key and cache use the script name.

## README defects

- The structure listing shows `3.5.3.non_topological_feature_extraction.py`
  twice and omits `3.4.2.Plot_ROC.py`, which exists in the repository.
- Step text elsewhere calls it `3.3.non_topological_feature_extraction.py`.

All affected files are excluded ML scripts, so there is no functional effect.

## Known discrepancies

- AFFECTS count: the paper (Table IV) states 212654; a script comment states
  212656. The validator accepts either observed value.

## Rules to confirm against the real files

TODO: Domain key form, `ProductType` spellings, `CWE-<n>` key form.
