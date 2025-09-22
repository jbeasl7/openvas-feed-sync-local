# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0197");
  script_cve_id("CVE-2024-36048");
  script_tag(name:"creation_date", value:"2024-05-30 04:12:16 +0000 (Thu, 30 May 2024)");
  script_version("2024-05-30T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-30 05:05:32 +0000 (Thu, 30 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0197)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0197");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0197.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33247");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/55ZLZN7U7KUGQ7YANJIPQP7R7ESP6B3L/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qtnetworkauth5, qtnetworkauth6' package(s) announced via the MGASA-2024-0197 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"QAbstractOAuth in Qt Network Authorization in Qt before 5.15.17, 6.x
before 6.2.13, 6.3.x through 6.5.x before 6.5.6, and 6.6.x through 6.7.x
before 6.7.1 uses only the time to seed the PRNG, which may result in
guessable values.");

  script_tag(name:"affected", value:"'qtnetworkauth5, qtnetworkauth6' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5networkauth-devel", rpm:"lib64qt5networkauth-devel~5.15.7~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5networkauth5", rpm:"lib64qt5networkauth5~5.15.7~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6networkauth-devel", rpm:"lib64qt6networkauth-devel~6.4.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6networkauth6", rpm:"lib64qt6networkauth6~6.4.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5networkauth-devel", rpm:"libqt5networkauth-devel~5.15.7~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5networkauth5", rpm:"libqt5networkauth5~5.15.7~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6networkauth-devel", rpm:"libqt6networkauth-devel~6.4.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6networkauth6", rpm:"libqt6networkauth6~6.4.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtnetworkauth5", rpm:"qtnetworkauth5~5.15.7~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtnetworkauth5-doc", rpm:"qtnetworkauth5-doc~5.15.7~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtnetworkauth6", rpm:"qtnetworkauth6~6.4.1~1.1.mga9", rls:"MAGEIA9"))) {
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
