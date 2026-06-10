# SharePoint "ToolShell" — Detection Rules & Defensive Tooling

Defensive repository for the 2025 Microsoft SharePoint **ToolShell** incident
(**CVE-2025-53770 / CVE-2025-53771**).



## 1. Detection rules (`sigma/`)

Three Sigma rules cover the main stages of the attack chain:

| Rule | Detects | ATT&CK | Level |
|------|---------|--------|-------|
| `01_toolshell_iis_request.yml` | `POST` to `ToolPane.aspx` with a `SignOut.aspx` referer | T1190 | high |
| `02_toolshell_aspx_file_create.yml` | `spinstall*.aspx` / `debug_dev.js` created in LAYOUTS | T1505.003 | critical |
| `03_w3wp_child_process.yml` | `w3wp.exe` spawning `cmd`/`powershell`/etc. | T1059, T1105 | high |

Convert them to your SIEM's query language with
[`sigma-cli`](https://github.com/SigmaHQ/sigma-cli), e.g.:

```bash
sigma convert -t splunk sigma/01_toolshell_iis_request.yml
```

## 2. Log scanner (`scanner/`)

A dependency-free Python 3 scanner that parses W3C-format IIS logs and flags the ToolShell request pattern and direct access to the `spinstall0.aspx` web shell. It is read-only and signature-light, meant to complement (not replace) behavior-based detection.

```bash
python scanner/scan_toolshell_iis.py samples/synthetic_iis.log
```

Example output against the provided synthetic log:

```
[ALERT] 2 suspicious event(s) found.
samples/synthetic_iis.log:6 src=203.0.113.50 method=POST uri=/_layouts/15/toolpane.aspx reason=ToolPane auth-bypass POST
samples/synthetic_iis.log:7 src=203.0.113.50 method=GET uri=/_layouts/15/spinstall0.aspx reason=spinstall0.aspx web-shell access
```

The two benign requests in the sample (`start.aspx`, `Home.aspx`) are correctly ignored.

## 3. Safe emulation (`emulation/`)

Generates benign, local artifacts so defenders can exercise the detection
pipeline without touching a real SharePoint server or the network:

```bash
python emulation/emulate_toolshell.py --out ./lab
python scanner/scan_toolshell_iis.py ./lab/logs/synthetic_iis.log
```

It writes a synthetic IIS log and a harmless, non-executable marker file in an **isolated** `lab/TEMPLATE/LAYOUTS/` path — never a real SharePoint directory, and never any cryptographic key material.

## References

- NVD — CVE-2025-53770: https://nvd.nist.gov/vuln/detail/CVE-2025-53770
- Microsoft MSRC customer guidance for CVE-2025-53770
- CISA Known Exploited Vulnerabilities catalog
- Unit 42, Trend Micro, Canadian Centre for Cyber Security, CSA Singapore advisories
