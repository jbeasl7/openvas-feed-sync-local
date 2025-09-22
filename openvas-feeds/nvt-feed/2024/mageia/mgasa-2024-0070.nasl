# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0070");
  script_cve_id("CVE-2018-16384", "CVE-2020-22669", "CVE-2021-35368", "CVE-2022-39955", "CVE-2022-39956", "CVE-2022-39957", "CVE-2022-39958");
  script_tag(name:"creation_date", value:"2024-03-19 04:12:13 +0000 (Tue, 19 Mar 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-21 18:55:56 +0000 (Wed, 21 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2024-0070)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0070");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0070.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30977");
  script_xref(name:"URL", value:"https://coreruleset.org/20210630/cve-2021-35368-crs-request-body-bypass/");
  script_xref(name:"URL", value:"https://coreruleset.org/20220919/crs-version-3-3-3-and-3-2-2-covering-several-cves/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/6MS5GMNYHFFIBWLJW7N3XAD24SLF3PFZ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/C4Q7DCCE37GT5ZBJOWP4NGUD4L3FAMDB/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3293");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-mod_security-crs' package(s) announced via the MGASA-2024-0070 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A SQL injection bypass (aka PL1 bypass) exists in OWASP ModSecurity Core
Rule Set (owasp-modsecurity-crs) through v3.1.0-rc3 via {`a`b} where a
is a special function name (such as 'if') and b is the SQL statement to
be executed. (CVE-2018-16384)
Modsecurity owasp-modsecurity-crs 3.2.0 (Paranoia level at PL1) has a
SQL injection bypass vulnerability. Attackers can use the comment
characters and variable assignments in the SQL syntax to bypass
Modsecurity WAF protection and implement SQL injection attacks on Web
applications. (CVE-2020-22669)
OWASP ModSecurity Core Rule Set 3.1.x before 3.1.2, 3.2.x before 3.2.1,
and 3.3.x before 3.3.2 is affected by a Request Body Bypass via a
trailing pathname. (CVE-2021-35368)
The OWASP ModSecurity Core Rule Set (CRS) is affected by a partial rule
set bypass by submitting a specially crafted HTTP Content-Type header
field that indicates multiple character encoding schemes. A vulnerable
back-end can potentially be exploited by declaring multiple Content-Type
'charset' names and therefore bypassing the configurable CRS
Content-Type header 'charset' allow list. An encoded payload can bypass
CRS detection this way and may then be decoded by the backend.
(CVE-2022-39955)
The OWASP ModSecurity Core Rule Set (CRS) is affected by a partial rule
set bypass for HTTP multipart requests by submitting a payload that uses
a character encoding scheme via the Content-Type or the deprecated
Content-Transfer-Encoding multipart MIME header fields that will not be
decoded and inspected by the web application firewall engine and the
rule set. The multipart payload will therefore bypass detection. A
vulnerable backend that supports these encoding schemes can potentially
be exploited. (CVE-2022-39956)
The OWASP ModSecurity Core Rule Set (CRS) is affected by a response body
bypass. A client can issue an HTTP Accept header field containing an
optional 'charset' parameter in order to receive the response in an
encoded form. Depending on the 'charset', this response can not be
decoded by the web application firewall. A restricted resource, access
to which would ordinarily be detected, may therefore bypass detection.
(CVE-2022-39957)
The OWASP ModSecurity Core Rule Set (CRS) is affected by a response body
bypass to sequentially exfiltrate small and undetectable sections of
data by repeatedly submitting an HTTP Range header field with a small
byte range. A restricted resource, access to which would ordinarily be
detected, may be exfiltrated from the backend, despite being protected
by a web application firewall that uses CRS. Short subsections of a
restricted resource may bypass pattern matching techniques and allow
undetected access. (CVE-2022-39958)");

  script_tag(name:"affected", value:"'apache-mod_security-crs' package(s) on Mageia 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

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

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_security-crs", rpm:"apache-mod_security-crs~3.3.5~1.mga9", rls:"MAGEIA9"))) {
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
