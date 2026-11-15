# Task → OWASP Sheets

Start with `find_sheets.py "<task words>"`. This table is a shortcut for common tasks. Sheet ids are passed to `read_section.py --sheet <id> --list`.

| Task | Primary sheets | Also useful |
|---|---|---|
| Login, signup, password reset | `Authentication`, `Password_Storage`, `Forgot_Password` | `Credential_Stuffing_Prevention`, `Multifactor_Authentication`, `Passkey_Security` |
| Sessions and cookies | `Session_Management`, `Cookie_Theft_Mitigation` | `Cross-Site_Request_Forgery_Prevention` |
| Authorization, roles, per-object access | `Authorization`, `Insecure_Direct_Object_Reference_Prevention` | `Access_Control`, `Multi_Tenant_Security`, `Authorization_Testing_Automation` |
| OAuth / OIDC / tokens | `OAuth2`, `JSON_Web_Token` | `SAML_Security` |
| Server Actions, route handlers, proxy | `Nextjs_Security` | `REST_Security`, `Mass_Assignment` |
| Rendering untrusted content | `Cross_Site_Scripting_Prevention`, `DOM_based_XSS_Prevention` | `React_Security` (draft), `DOM_Clobbering_Prevention` |
| CSP and security headers | `Content_Security_Policy`, `HTTP_Headers` | `HTTP_Strict_Transport_Security`, `Clickjacking_Defense` |
| Forms and input | `Input_Validation`, `Mass_Assignment` | `Email_Validation_and_Verification`, `Bot_Management_and_Anti-Automation` |
| Database queries | `SQL_Injection_Prevention`, `Query_Parameterization` | `Database_Security`, `NoSQL_Security` |
| Fetching user-supplied URLs | `Server_Side_Request_Forgery_Prevention` | `Unvalidated_Redirects_and_Forwards` |
| File upload | `File_Upload` | `Denial_of_Service` |
| Webhooks (CMS, payments) | `Webhook_Security` | `Third_Party_Payment_Gateway_Integration` |
| Caching personalized pages | `Web_Cache_Security`, `Nextjs_Security` | `Session_Management` |
| Secrets and environment variables | `Secrets_Management` | `Key_Management`, `Cryptographic_Storage` |
| Dependencies and supply chain | `NPM_Security`, `Vulnerable_Dependency_Management` | `Software_Supply_Chain_Security`, `Dependency_Graph_SBOM` |
| Third-party scripts and embeds | `Third_Party_Javascript_Management` | `HTML5_Security` |
| Docker images and Compose | `Docker_Security`, `NodeJS_Docker` | `Network_Segmentation`, `Infrastructure_as_Code_Security` |
| GitHub Actions and CI | `GitHub_Actions_Security`, `CI_CD_Security` | `Workload_Identity_Federation` |
| Rate limiting and abuse | `Denial_of_Service`, `Bot_Management_and_Anti-Automation` | `Credential_Stuffing_Prevention` |
| Logging and errors | `Logging`, `Error_Handling` | `Logging_Vocabulary` |
| AI features, agents, MCP | `LLM_Prompt_Injection_Prevention`, `AI_Agent_Security`, `MCP_Security` | `RAG_Security`, `Secure_Coding_with_AI` |
| Threat modeling a feature | `Threat_Modeling` | `Attack_Surface_Analysis`, `Abuse_Case` |
| Privacy and user data | `User_Privacy_Protection` | `Cryptographic_Storage` |

## Answer pattern

1. Run `find_sheets.py` with the user's words, plus `--stack-root` when there's a repo.
2. Read the 1–3 best sections.
3. Answer in terms of the user's code and stack, with a concrete fix, not a generic recap.
4. Cite each OWASP-backed claim as **sheet › section** with the printed URL. Flag draft sheets.
5. If OWASP doesn't cover something, say so rather than stretching a citation.
