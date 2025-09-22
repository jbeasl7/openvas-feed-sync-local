# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0258");
  script_cve_id("CVE-2024-36387", "CVE-2024-38473", "CVE-2024-38474", "CVE-2024-38475", "CVE-2024-38476", "CVE-2024-38477", "CVE-2024-39573", "CVE-2024-39884");
  script_tag(name:"creation_date", value:"2024-07-10 04:12:51 +0000 (Wed, 10 Jul 2024)");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-21 15:08:56 +0000 (Wed, 21 Aug 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0258)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0258");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0258.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33353");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/01/10");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/01/11");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/01/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/01/6");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/01/7");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/01/8");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/01/9");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/07/03/8");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache' package(s) announced via the MGASA-2024-0258 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Serving WebSocket protocol upgrades over a HTTP/2 connection could
result in a Null Pointer dereference, leading to a crash of the server
process, degrading performance. (CVE-2024-36387)
Encoding problem in mod_proxy in Apache HTTP Server 2.4.59 and earlier
allows request URLs with incorrect encoding to be sent to backend
services, potentially bypassing authentication via crafted requests.
(CVE-2024-38473)
Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59
and earlier allows attacker to execute scripts in directories permitted
by the configuration but not directly reachable by any URL or source
disclosure of scripts meant to only to be executed as CGI. Some
RewriteRules that capture and substitute unsafely will now fail unless
rewrite flag 'UnsafeAllow3F' is specified. (CVE-2024-38474)
Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59
and earlier allows an attacker to map URLs to filesystem locations that
are permitted to be served by the server but are not
intentionally/directly reachable by any URL, resulting in code execution
or source code disclosure. Substitutions in server context that use a
backreferences or variables as the first segment of the substitution are
affected. Some unsafe RewiteRules will be broken by this change and the
rewrite flag 'UnsafePrefixStat' can be used to opt back in once ensuring
the substitution is appropriately constrained. (CVE-2024-38475)
Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are
vulnerably to information disclosure, SSRF or local script execution via
backend applications whose response headers are malicious or
exploitable. (CVE-2024-38476)
Null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and
earlier allows an attacker to crash the server via a malicious request.
(CVE-2024-38477)
Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier
allows an attacker to cause unsafe RewriteRules to unexpectedly setup
URL's to be handled by mod_proxy. (CVE-2024-39573)
A regression in the core of Apache HTTP Server 2.4.60 ignores some use
of the legacy content-type based configuration of handlers.
'AddType' and similar configuration, under some circumstances where
files are requested indirectly, result in source code disclosure of local
content. For example, PHP scripts may be served instead of interpreted.
(CVE-2024-39884)");

  script_tag(name:"affected", value:"'apache' package(s) on Mageia 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"apache", rpm:"apache~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-doc", rpm:"apache-doc~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_brotli", rpm:"apache-mod_brotli~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_http2", rpm:"apache-mod_http2~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy_html", rpm:"apache-mod_proxy_html~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_session", rpm:"apache-mod_session~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_suexec", rpm:"apache-mod_suexec~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.4.61~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
