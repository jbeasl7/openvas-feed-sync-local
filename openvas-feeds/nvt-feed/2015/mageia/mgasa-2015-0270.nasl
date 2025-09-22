# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130108");
  script_cve_id("CVE-2015-3258", "CVE-2015-3279");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:48 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0270)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0270");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0270.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16221");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1235385");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238990");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups-filters' package(s) announced via the MGASA-2015-0270 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow was discovered in the way the texttopdf
utility of cups-filters processed print jobs with a specially crafted line
size. An attacker being able to submit print jobs could exploit this flaw
to crash texttopdf or, possibly, execute arbitrary code with the
privileges of the 'lp' user (CVE-2015-3258, CVE-2015-3279).");

  script_tag(name:"affected", value:"'cups-filters' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"cups-filters", rpm:"cups-filters~1.0.53~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups-filters-devel", rpm:"lib64cups-filters-devel~1.0.53~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups-filters1", rpm:"lib64cups-filters1~1.0.53~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups-filters-devel", rpm:"libcups-filters-devel~1.0.53~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups-filters1", rpm:"libcups-filters1~1.0.53~1.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"cups-filters", rpm:"cups-filters~1.0.71~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups-filters-devel", rpm:"lib64cups-filters-devel~1.0.71~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups-filters1", rpm:"lib64cups-filters1~1.0.71~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups-filters-devel", rpm:"libcups-filters-devel~1.0.71~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups-filters1", rpm:"libcups-filters1~1.0.71~1.mga5", rls:"MAGEIA5"))) {
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
