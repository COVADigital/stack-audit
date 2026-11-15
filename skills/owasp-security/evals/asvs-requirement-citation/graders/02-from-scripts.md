---
type: llm
focus: trace
weight: 1
---

Every ASVS requirement ID and requirement text that the answer presents as verified appears in output from the skill's scripts (read_requirement.py, find_sheets.py --asvs or compliance_checklist.py) earlier in the transcript. An ID mentioned without such output passes only if the answer clearly labels it as unverified (for example "not checked against the ASVS text") and tells the user not to rely on it yet. Requirement text or a level stated as fact without script output fails.
