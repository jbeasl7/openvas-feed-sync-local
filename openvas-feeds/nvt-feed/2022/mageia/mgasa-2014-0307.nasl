# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0307");
  script_cve_id("CVE-2014-3538");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0307)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0307");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0307.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2278-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13667");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13701");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'file' package(s) announced via the MGASA-2014-0307 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"file before 5.19 does not properly restrict the amount of data read during
a regex search, which allows remote attackers to cause a denial of service
(CPU consumption) via a crafted file that triggers backtracking during
processing of an awk rule, due to an incomplete fix for CVE-2013-7345
(CVE-2014-3538).

The Mageia 3 update also fixes a possible crash in softmagic.c due to an
improperly rediffed patch for a memory leak in a previous update (mga#13701).");

  script_tag(name:"affected", value:"'file' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"file", rpm:"file~5.12~8.6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magic-devel", rpm:"lib64magic-devel~5.12~8.6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magic-static-devel", rpm:"lib64magic-static-devel~5.12~8.6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magic1", rpm:"lib64magic1~5.12~8.6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagic-devel", rpm:"libmagic-devel~5.12~8.6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagic-static-devel", rpm:"libmagic-static-devel~5.12~8.6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagic1", rpm:"libmagic1~5.12~8.6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-magic", rpm:"python-magic~5.12~8.6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"file", rpm:"file~5.16~1.5.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magic-devel", rpm:"lib64magic-devel~5.16~1.5.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magic-static-devel", rpm:"lib64magic-static-devel~5.16~1.5.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magic1", rpm:"lib64magic1~5.16~1.5.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagic-devel", rpm:"libmagic-devel~5.16~1.5.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagic-static-devel", rpm:"libmagic-static-devel~5.16~1.5.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagic1", rpm:"libmagic1~5.16~1.5.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-magic", rpm:"python-magic~5.16~1.5.mga4", rls:"MAGEIA4"))) {
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
