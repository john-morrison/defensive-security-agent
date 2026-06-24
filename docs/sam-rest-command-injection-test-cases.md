# SAM REST Command Injection Test Cases

These test cases demonstrate the verified SAMRESTServices command-injection traces using harmless marker-file payloads. Run them only against an authorized dev or test instance.

The PoC runner is dry-run by default:

```bash
cd /Users/johnm/codex_general/my_projects/defensive-security-agent
python3 scripts/sam_rest_command_injection_pocs.py \
  --base-url http://HOST:PORT/bugdb
```

To execute against an authorized test target:

```bash
python3 scripts/sam_rest_command_injection_pocs.py \
  --base-url http://HOST:PORT/bugdb \
  --execute \
  --i-understand-authorized-test
```

The Windows `cmd /c` cases write harmless marker files under `%TEMP%` on the server. Verify on the server with the command printed by the runner, for example:

```cmd
type "%TEMP%\dsa_samrest_workspace.txt"
```

## Cases

| Case | Trace | Endpoint | Evidence |
| --- | --- | --- | --- |
| `workspace` | `RestController.java:583` | `GET /workspace/owner/{owner}/fixby/{fixby}/wsname/{wsname}/bugnumber/{bugnumber}` | `owner` closes a quoted argument and appends a benign `echo` command. |
| `clearcase` | `RestController.java:622`, `RestController.java:648` | `GET /clearcase/pb/{pbname}` | `pbname` is concatenated into `cmd /c` without quoting or allowlisting. |
| `svn_old` | `RestController.java:734` | `GET /svn_old/fixby/{fixby}?branch=...` | `fixby` is concatenated unquoted after `--codeline`. |
| `svn_sam` | `RestController.java:852` | `GET /svn?branch=...&fixby=...` | `fixby` is concatenated unquoted after `--codeline`. |
| `orahubmerge-argument-injection` | `RestController.java:1210` | `POST /orahubmerge/` | `sourceBranch` reaches `Runtime.exec(String)` arguments. Treat this as argument injection unless the invoked Perl script proves OS command execution. |

## Bug Filing Notes

For each bug, include:

- vulnerable method and line number from `sam-rest-verification-report.md`
- source parameter and sink line
- generated curl command from the PoC runner
- server-side marker-file verification output
- expected fix: replace `Runtime.exec(String)` and `cmd /c` with fixed executable plus argument array, and reject or allowlist request-controlled values before process execution

