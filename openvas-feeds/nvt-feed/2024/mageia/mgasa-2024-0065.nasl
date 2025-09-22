# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0065");
  script_cve_id("CVE-2023-29491");
  script_tag(name:"creation_date", value:"2024-03-18 04:11:54 +0000 (Mon, 18 Mar 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-24 13:23:52 +0000 (Mon, 24 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0065)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0065");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0065.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31792");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-May/014766.html");
  script_xref(name:"URL", value:"https://lwn.net/Articles/952268/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6099-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/04/12/5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ncurses' package(s) announced via the MGASA-2024-0065 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability:
Local users can trigger security-relevant memory corruption via
malformed data. (CVE-2023-29491)");

  script_tag(name:"affected", value:"'ncurses' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ncurses++6", rpm:"lib64ncurses++6~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncurses-devel", rpm:"lib64ncurses-devel~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncurses5", rpm:"lib64ncurses5~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncurses6", rpm:"lib64ncurses6~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncursesw++6", rpm:"lib64ncursesw++6~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncursesw-devel", rpm:"lib64ncursesw-devel~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncursesw5", rpm:"lib64ncursesw5~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ncursesw6", rpm:"lib64ncursesw6~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses++6", rpm:"libncurses++6~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses-devel", rpm:"libncurses-devel~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses5", rpm:"libncurses5~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses6", rpm:"libncurses6~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncursesw++6", rpm:"libncursesw++6~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncursesw-devel", rpm:"libncursesw-devel~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncursesw5", rpm:"libncursesw5~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncursesw6", rpm:"libncursesw6~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ncurses", rpm:"ncurses~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ncurses-extraterms", rpm:"ncurses-extraterms~6.3~20221203.2.1.mga9", rls:"MAGEIA9"))) {
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
