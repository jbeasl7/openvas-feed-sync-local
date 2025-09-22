# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0268");
  script_cve_id("CVE-2013-5648");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0268)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0268");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0268.html");
  script_xref(name:"URL", value:"http://www.id.ee/?lang=en&id=34283#3_7_2");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11100");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libdigidoc' package(s) announced via the MGASA-2013-0268 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libdigidoc packages fix security vulnerability:

Fixed one critical bug in the DDOC parsing routines. By persuading a victim to
open a specially-crafted DDOC file, a remote attacker could exploit this
vulnerability to overwrite arbitrary files on the system with the privileges
of the victim (CVE-2013-5648).");

  script_tag(name:"affected", value:"'libdigidoc' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"lib64digidoc-devel", rpm:"lib64digidoc-devel~2.7.1.59~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digidoc2", rpm:"lib64digidoc2~2.7.1.59~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigidoc", rpm:"libdigidoc~2.7.1.59~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigidoc-devel", rpm:"libdigidoc-devel~2.7.1.59~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigidoc2", rpm:"libdigidoc2~2.7.1.59~1.1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64digidoc-devel", rpm:"lib64digidoc-devel~3.6.0.0~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digidoc2", rpm:"lib64digidoc2~3.6.0.0~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigidoc", rpm:"libdigidoc~3.6.0.0~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigidoc-devel", rpm:"libdigidoc-devel~3.6.0.0~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigidoc2", rpm:"libdigidoc2~3.6.0.0~3.1.mga3", rls:"MAGEIA3"))) {
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
