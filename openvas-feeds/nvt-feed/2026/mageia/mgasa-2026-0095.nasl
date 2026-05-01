# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0095");
  script_cve_id("CVE-2026-24880", "CVE-2026-25854", "CVE-2026-29129", "CVE-2026-29145", "CVE-2026-29146", "CVE-2026-32990", "CVE-2026-34483", "CVE-2026-34486", "CVE-2026-34487", "CVE-2026-34500");
  script_tag(name:"creation_date", value:"2026-04-13 05:06:37 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-13T06:24:05+0000");
  script_tag(name:"last_modification", value:"2026-04-13 06:24:05 +0000 (Mon, 13 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0095)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0095");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0095.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35341");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/09/20");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/09/21");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/09/22");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/09/23");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/09/24");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/09/25");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/09/26");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/09/27");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/09/28");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/04/09/29");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the MGASA-2026-0095 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Request smuggling via invalid chunk extension. (CVE-2026-24880)
Occasionally open redirect. (CVE-2026-25854)
TLS cipher order is not preserved. (CVE-2026-29129)
OCSP checks sometimes soft-fail even when soft-fail is disabled.
(CVE-2026-29145)
EncryptInterceptor vulnerable to padding oracle attack by default.
(CVE-2026-29146)
Fix for CVE-2025-66614 is incomplete. (CVE-2026-32990)
Incomplete escaping of JSON access logs. (CVE-2026-34483)
Fix for CVE-2026-29146 allowed bypass of EncryptInterceptor.
(CVE-2026-34486)
Cloud membership for clustering component exposed the Kubernetes bearer
token. (CVE-2026-34487)
OCSP checks sometimes soft-fail with FFM even when soft-fail is
disabled. (CVE-2026-34500)");

  script_tag(name:"affected", value:"'tomcat' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.117~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.117~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~9.0.117~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3.0-api", rpm:"tomcat-el-3.0-api~9.0.117~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2.3-api", rpm:"tomcat-jsp-2.3-api~9.0.117~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.117~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4.0-api", rpm:"tomcat-servlet-4.0-api~9.0.117~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.117~1.mga9", rls:"MAGEIA9"))) {
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
