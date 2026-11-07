# my-agent (clean export)

This is a sanitized export of a private home-automation and assistant codebase, made so cloud coding
sessions can read and change the code. It is **not runnable as is**: the live system depends on local
services, local files and private values that are deliberately not here. Each commit here is one whole
export; the source repo's own history never leaves its machine.

Exported from source commit `c227583d8d93` by `git-tools/export_clean.py` (a copy is here; the map and the
private terms list it needs are not). 150 of 890 tracked
files are here; the rest were left out on purpose (table below).

## Placeholders

Private values (names, addresses, hostnames, account ids) were replaced with `{{PLACEHOLDER}}` tokens.
Treat them as opaque constants:

- Keep every placeholder exactly as written. Do not guess, fill in or "fix" a value.
- A suffix shows the original letter case: `_LC` lower, `_UC` upper, `_TC` capitalised.
- `{{IP_a_b_c_d}}` stands for the ordinary test address a.b.c.d (13 uses); it is a placeholder only
  because the secret scanner refuses private address ranges.
- Lines ending in `secret-scan: allow [export-reviewed]` are reviewed test fixtures and canaries. Leave the marker alone.
- New code that needs a private value should read it from configuration or an environment variable.
- Fictional phone-number fixtures use the unassigned area code 999 with 555 exchanges; keep them fictional.
- The six PNGs in `dashboard/icons/` are code-drawn orbs: chunk-only PNGs (IHDR, IDAT, IEND, no metadata),
  pixel-identical (and byte-identical) to the output of the source repo's icon generator script.
- A few self-tests compare against the private values themselves (for example the name-hiding and
  vault-search checks) and fail in this export; they pass on the source. Tests that need local services,
  private folders or the owner's machine cannot run here at all.

| Placeholder | Stands for | Uses |
|---|---|---|
| `{{CONTACT_NAME_1}}` | a relative's first name | 2 |
| `{{CUSTOMER_NAME_1}}` | a customer's name | 7 |
| `{{FAMILY_NAME_1}}` | a family member's first name | 1 |
| `{{FAMILY_NOTE_1}}` | the title of a family member's vault note | 1 |
| `{{HOME_LAN_NET}}` | the home LAN network address (used with /24) | 8 |
| `{{HOME_STATE}}` | the home state | 1 |
| `{{HOME_TOWN}}` | the home town | 1 |
| `{{JR_VM_UUID}}` | the Jr VirtualBox VM id | 3 |
| `{{NAS_IP}}` | the NAS's LAN address | 4 |
| `{{NAS_MODEL}}` | the NAS model name | 23 |
| `{{OWNER_GMAIL}}` | the owner's Gmail address | 1 |
| `{{TAILNET_HOST}}` | the PC's full tailnet DNS name | 9 |
| `{{VOICE_ID_DECOY_1}}` | a retired text-to-speech voice id | 1 |
| `{{VOICE_ID_DECOY_2}}` | an unused text-to-speech voice id | 1 |
| `{{VOICE_ID_LIVE}}` | the live text-to-speech voice id | 1 |
| `{{WIN_SID}}` | the Windows account SID | 1 |
| `{{WIN_USER}}` | the Windows account name (C:/Users/<name>) | 166 |

## What was left out

| Reason | Files |
|---|---|
| boot-file | 2 |
| known-dirty-list | 1 |
| literal-collision | 1 |
| local-runtime-config | 3 |
| personal-document | 1 |
| scan-unclean | 1 |
| staged-tree | 731 |

Boot files (`CLAUDE.md`, `AGENTS.md`) are replaced by `CLAUDE.example.md`, which describes their structure.

## How changes get back

Work on a branch and open a pull request. The owner exports the PR as a unified diff, maps placeholders back
to real values locally with `git-tools/import_patch.py`, reviews the result and applies it by hand. Nothing
in this repository is deployed automatically.
