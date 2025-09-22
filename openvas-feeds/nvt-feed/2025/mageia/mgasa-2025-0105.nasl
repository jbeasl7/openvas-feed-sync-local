# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0105");
  script_cve_id("CVE-2004-56337", "CVE-2025-24813");
  script_tag(name:"creation_date", value:"2025-03-20 04:09:19 +0000 (Thu, 20 Mar 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-18 14:15:43 +0000 (Tue, 18 Mar 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0105)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0105");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0105.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34112");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/WQRQ6JSFISH4LSDOH7IDJHNYPKMGUF5X/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the MGASA-2025-0105 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in
Apache Tomcat. This issue affects Apache Tomcat: from 11.0.0-M1 through
11.0.1, from 10.1.0-M1 through 10.1.33, from 9.0.0.M1 through 9.0.97.
The mitigation for CVE-2024-50379 was incomplete. Users running Tomcat
on a case insensitive file system with the default servlet write enabled
(readonly initialisation parameter set to the non-default value of
false) may need additional configuration to fully mitigate
CVE-2024-50379 depending on which version of Java they are using with
Tomcat: - running on Java 8 or Java 11: the system property
sun.io.useCanonCaches must be explicitly set to false (it defaults to
true) - running on Java 17: the system property sun.io.useCanonCaches,
if set, must be set to false (it defaults to false) - running on Java 21
onwards: no further configuration is required (the system property and
the problematic cache have been removed) Tomcat 11.0.3, 10.1.35 and
9.0.99 onwards will include checks that sun.io.useCanonCaches is set
appropriately before allowing the default servlet to be write enabled on
a case insensitive file system. Tomcat will also set
sun.io.useCanonCaches to false by default where it can. (CVE-2004-56337)
Path Equivalence: 'file.Name' (Internal Dot) leading to Remote Code
Execution and/or Information disclosure and/or malicious content added
to uploaded files via write enabled Default Servlet in Apache Tomcat.
This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.2, from
10.1.0-M1 through 10.1.34, from 9.0.0.M1 through 9.0.98. If all of the
following were true, a malicious user was able to view security
sensitive files and/or inject content into those files: - writes enabled
for the default servlet (disabled by default) - support for partial PUT
(enabled by default) - a target URL for security sensitive uploads that
was a sub-directory of a target URL for public uploads - attacker
knowledge of the names of security sensitive files being uploaded - the
security sensitive files also being uploaded via partial PUT If all of
the following were true, a malicious user was able to perform remote
code execution: - writes enabled for the default servlet (disabled by
default) - support for partial PUT (enabled by default) - application
was using Tomcat's file based session persistence with the default
storage location - application included a library that may be leveraged
in a deserialization attack Users are recommended to upgrade to version
11.0.3, 10.1.35 or 9.0.99, which fixes the issue (CVE-2025-24813).");

  script_tag(name:"affected", value:"'tomcat' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.102~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.102~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~9.0.102~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3.0-api", rpm:"tomcat-el-3.0-api~9.0.102~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2.3-api", rpm:"tomcat-jsp-2.3-api~9.0.102~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.102~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4.0-api", rpm:"tomcat-servlet-4.0-api~9.0.102~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.102~1.mga9", rls:"MAGEIA9"))) {
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
