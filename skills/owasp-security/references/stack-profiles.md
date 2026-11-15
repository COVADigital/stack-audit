# Stack Profiles: Curated Sheet Sets

Use these when scoping a project or a feature, or when the user asks "what security guidance applies to us?". Every id is checked against the catalog by the test suite.

## Next.js App Router app (Next.js 16, React 19)

- **Always:** `Nextjs_Security`, `Cross_Site_Scripting_Prevention`, `Content_Security_Policy`, `HTTP_Headers`, `Secrets_Management`, `NPM_Security`
- **With accounts:** `Authentication`, `Session_Management`, `Authorization`, `Insecure_Direct_Object_Reference_Prevention`, `Cross-Site_Request_Forgery_Prevention`
- **With personalized caching:** `Web_Cache_Security`
- **Language level:** `JavaScript_and_TypeScript_Security`, `Nodejs_Security`, `Prototype_Pollution_Prevention`
- **React specifics:** `React_Security` (**draft**: cite with that label)

## Auth via a managed library (Better Auth, Auth.js, Clerk)

Use these to *verify the configuration*, not to rebuild it: `Authentication`, `Session_Management`, `Password_Storage`, `Multifactor_Authentication`, `Passkey_Security`, `Credential_Stuffing_Prevention`, `OAuth2`.

## CMS-driven site (Sanity webhooks, ISR)

`Webhook_Security`, `Web_Cache_Security`, `Cross_Site_Scripting_Prevention` (rich text rendering), `Third_Party_Javascript_Management` (embeds).

## Data layer (PostgreSQL, Drizzle)

`SQL_Injection_Prevention`, `Query_Parameterization`, `Database_Security`, `Mass_Assignment`, `Multi_Tenant_Security` (if tenants share tables).

## Docker / Compose / Coolify

`Docker_Security`, `NodeJS_Docker`, `Secrets_Management`, `Network_Segmentation`, `Infrastructure_as_Code_Security`.

## CI/CD and repository

`GitHub_Actions_Security`, `CI_CD_Security`, `Software_Supply_Chain_Security`, `Vulnerable_Dependency_Management`, `Dependency_Graph_SBOM`.

## AI features, agents, MCP servers

`LLM_Prompt_Injection_Prevention`, `AI_Agent_Security`, `MCP_Security`, `RAG_Security`, `Secure_Coding_with_AI`.
