# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0073");
  script_cve_id("CVE-2023-2137", "CVE-2023-7104");
  script_tag(name:"creation_date", value:"2024-04-05 04:13:15 +0000 (Fri, 05 Apr 2024)");
  script_version("2024-04-05T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-04-05 05:05:37 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-26 20:48:18 +0000 (Wed, 26 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0073)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0073");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0073.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31868");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/04/stable-channel-update-for-desktop_18.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6566-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite3' package(s) announced via the MGASA-2024-0073 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
Heap buffer overflow in sqlite. (CVE-2023-2137)
A vulnerability was found in SQLite SQLite3 up to 3.43.0 and classified
as critical. This issue affects the function sessionReadRecord of the
file ext/session/sqlite3session.c of the component make alltest Handler.
The manipulation leads to heap-based buffer overflow. (CVE-2023-7104)");

  script_tag(name:"affected", value:"'sqlite3' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lemon", rpm:"lemon~3.40.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3-devel", rpm:"lib64sqlite3-devel~3.40.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3-static-devel", rpm:"lib64sqlite3-static-devel~3.40.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3_0", rpm:"lib64sqlite3_0~3.40.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-devel", rpm:"libsqlite3-devel~3.40.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-static-devel", rpm:"libsqlite3-static-devel~3.40.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3_0", rpm:"libsqlite3_0~3.40.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3", rpm:"sqlite3~3.40.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-tcl", rpm:"sqlite3-tcl~3.40.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-tools", rpm:"sqlite3-tools~3.40.1~1.1.mga9", rls:"MAGEIA9"))) {
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
