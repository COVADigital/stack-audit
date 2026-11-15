---
type: llm
focus: trace
weight: 1
---

If the skill's scripts printed ASVS output (read_requirement.py or find_sheets.py --asvs), the answer includes the citation link they printed: a github.com/OWASP/ASVS URL at the v5.0.0_release tag pointing at the V3.3 Cookie Setup section. If the scripts reported that the OWASP data (cheat sheet clone or ASVS file) is missing, the answer instead gives no ASVS or OWASP link that the scripts did not print (or clearly labels any such link as unverified) and says how to enable verified citations.
