from pathlib import Path

kb_path = Path("cve_knowledge_base.md").resolve()
print("Using KB file:", kb_path)

kb_path.write_text(
    """# CVE & CWE Knowledge Base (Service Side — Partner A)

## vsFTPd 2.3.4 Backdoor (CVE-2011-2523 / CWE-78)
- **Service / Banner:** `vsFTPd 2.3.4` (Port 2121/tcp)
- **Severity:** Critical
- **Reference:** CVE-2011-2523, CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **Source:** NVD (CVE-2011-2523), Rapid7 / Metasploit `unix/ftp/vsftpd_234_backdoor` advisory
- **Remediation:** Replace the compromised `vsftpd 2.3.4` binary with a verified package from a trusted distribution repository, audit the host for unauthorized processes/listeners (such as port 6200), and rotate credentials.

## Anonymous FTP Access (CWE-220 / CWE-287)
- **Service / Banner:** FTP anonymous login enabled (`230 Login successful.`, Port 2121/tcp)
- **Severity:** High
- **Reference:** CWE-220 (Storage of File With Sensitive Data Under FTP Root), CWE-287 (Improper Authentication)
- **Source:** MITRE CWE-220, MITRE CWE-287, CIS Distribution Independent Linux Benchmark (FTP service hardening)
- **Remediation:** Set `anonymous_enable=NO` in `vsftpd.conf`, enforce authenticated SFTP/FTPS access, and audit FTP root directories for exposed or writable files.

## Apache HTTP Server 2.2.8 EOL & DAV/2 Exposure (CVE-2017-9798, CVE-2014-0118, CVE-2013-6438)
- **Service / Banner:** `Apache/2.2.8 (Ubuntu) DAV/2` (Port 8080/tcp)
- **Severity:** High
- **Reference:** CVE-2017-9798 (Optionsbleed), CVE-2014-0118 (`mod_deflate` DoS), CVE-2013-6438 (`mod_dav` write-buffer overflow), CWE-1104 (Use of Unmaintained Third Party Components)
- **Source:** Apache HTTP Server 2.2 Vulnerabilities Archive, NVD (CVE-2017-9798, CVE-2014-0118, CVE-2013-6438)
- **Remediation:** Upgrade from end-of-life Apache 2.2.8 to a supported Apache 2.4.x release, disable `mod_dav` (`a2dismod dav dav_fs`) if unused, and set `ServerTokens Prod` and `ServerSignature Off`.

## Legacy PHP 5.2.4 Exposure & Header Disclosure (CVE-2010-2225, CVE-2011-1398, CWE-200)
- **Service / Banner:** `X-Powered-By: PHP/5.2.4-2ubuntu5.10` (Port 8080/tcp)
- **Severity:** High
- **Reference:** CVE-2010-2225 (`SplObjectStorage` deserialization UAF), CVE-2011-1398 (SAPI header injection), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Source:** NVD (CVE-2010-2225, CVE-2011-1398), PHP Unsupported Branches Archive, MITRE CWE-200
- **Remediation:** Upgrade from end-of-life PHP 5.2.4 to a supported PHP 8.x release, set `expose_php = Off` in `php.ini` to suppress `X-Powered-By`, and audit application input/deserialization paths.
""",
    encoding="utf-8",
)

blocks = [b.strip() for b in kb_path.read_text(encoding="utf-8").split("\n## ") if b.strip()]
print("Parsed blocks count:", len(blocks))