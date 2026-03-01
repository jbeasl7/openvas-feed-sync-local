# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0035");
  script_cve_id("CVE-2025-61726", "CVE-2025-61728", "CVE-2025-61730", "CVE-2025-61731", "CVE-2025-61732", "CVE-2025-68119", "CVE-2025-68121");
  script_tag(name:"creation_date", value:"2026-02-12 04:44:41 +0000 (Thu, 12 Feb 2026)");
  script_version("2026-02-12T05:59:59+0000");
  script_tag(name:"last_modification", value:"2026-02-12 05:59:59 +0000 (Thu, 12 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-10 16:08:03 +0000 (Tue, 10 Feb 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0035)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0035");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0035.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35007");
  script_xref(name:"URL", value:"https://groups.google.com/g/golang-announce/c/Vd2tYVM8eUc");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/NH2ETRY5I4475P2G36TA426YNBGAZLJM/");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2026/01/17/2");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2026/01/17/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/01/15/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/02/07/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2026-0035 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"net/http: memory exhaustion in Request.ParseForm. (CVE-2025-61726)
archive/zip: denial of service when parsing arbitrary ZIP archives.
(CVE-2025-61728)
crypto/tls: handshake messages may be processed at the incorrect
encryption level. (CVE-2025-61730)
cmd/go: bypass of flag sanitization can lead to arbitrary code
execution. (CVE-2025-61731)
Potential code smuggling via doc comments in cmd/cgo. (CVE-2025-61732)
cmd/go: unexpected code execution when invoking toolchain.
(CVE-2025-68119)
crypto/tls: Config.Clone copies automatically generated session ticket
keys, session resumption does not account for the expiration of full
certificate chain. (CVE-2025-68121)");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.24.13~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.24.13~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.24.13~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.24.13~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.24.13~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.24.13~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.24.13~1.mga9", rls:"MAGEIA9"))) {
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
