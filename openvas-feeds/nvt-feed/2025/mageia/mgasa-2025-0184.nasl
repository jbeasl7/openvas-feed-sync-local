# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0184");
  script_cve_id("CVE-2025-0913", "CVE-2025-22874", "CVE-2025-4673");
  script_tag(name:"creation_date", value:"2025-06-12 04:12:04 +0000 (Thu, 12 Jun 2025)");
  script_version("2025-06-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-06-12 05:40:18 +0000 (Thu, 12 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0184)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0184");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0184.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34353");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/06/05/5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2025-0184 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Proxy-Authorization and Proxy-Authenticate headers persisted on
cross-origin redirects potentially leaking sensitive information.
CVE-2025-4673.
os: inconsistent handling of O_CREATE<pipe>O_EXCL on Unix and Windows
os.OpenFile(path, os.O_CREATE<pipe>O_EXCL) behaved differently on Unix and
Windows systems when the target path was a dangling symlink. On Unix
systems, OpenFile with O_CREATE and O_EXCL flags never follows symlinks.
On Windows, when the target path was a symlink to a nonexistent
location, OpenFile would create a file in that location - CVE-2025-0913.
crypto/x509: usage of ExtKeyUsageAny disables policy validation. Calling
Verify with a VerifyOptions.KeyUsages that contains ExtKeyUsageAny
unintentionally disabledpolicy validation. This only affected
certificate chains which contain policy graphs, which are rather
uncommon - CVE-2025-22874.
OpenFile now always returns an error when the O_CREATE and O_EXCL
flags are both set and the target path is a symlink.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.24.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.24.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.24.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.24.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.24.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.24.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.24.4~1.mga9", rls:"MAGEIA9"))) {
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
