# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0096");
  script_cve_id("CVE-2023-6597", "CVE-2024-0450");
  script_tag(name:"creation_date", value:"2024-04-05 04:13:15 +0000 (Fri, 05 Apr 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0096)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0096");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0096.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32998");
  script_xref(name:"URL", value:"https://lwn.net/Articles/966564/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/03/20/5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python, python3' package(s) announced via the MGASA-2024-0096 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The tempfile.TemporaryDirectory class would dereference symlinks during
cleanup of permissions-related errors. This means users which can run
privileged programs are potentially able to modify permissions of files
referenced by symlinks in some circumstances. (CVE-2023-6597)
The zipfile module is vulnerable to 'quoted-overlap' zip-bombs which
exploit the zip format to create a zip-bomb with a high compression
ratio. The fixed versions of CPython makes the zipfile module reject zip
archives which overlap entries in the archive. (CVE-2024-0450)");

  script_tag(name:"affected", value:"'python, python3' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64python-devel", rpm:"lib64python-devel~2.7.18~15.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7", rpm:"lib64python2.7~2.7.18~15.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7-stdlib", rpm:"lib64python2.7-stdlib~2.7.18~15.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7-testsuite", rpm:"lib64python2.7-testsuite~2.7.18~15.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3-devel", rpm:"lib64python3-devel~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10", rpm:"lib64python3.10~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10-stdlib", rpm:"lib64python3.10-stdlib~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10-testsuite", rpm:"lib64python3.10-testsuite~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython-devel", rpm:"libpython-devel~2.7.18~15.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7", rpm:"libpython2.7~2.7.18~15.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7-stdlib", rpm:"libpython2.7-stdlib~2.7.18~15.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7-testsuite", rpm:"libpython2.7-testsuite~2.7.18~15.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3-devel", rpm:"libpython3-devel~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10", rpm:"libpython3.10~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10-stdlib", rpm:"libpython3.10-stdlib~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10-testsuite", rpm:"libpython3.10-testsuite~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.18~15.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.7.18~15.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3", rpm:"tkinter3~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3-apps", rpm:"tkinter3-apps~3.10.11~1.2.mga9", rls:"MAGEIA9"))) {
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
