# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0481");
  script_cve_id("CVE-2014-8627", "CVE-2014-8628");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0481)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0481");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0481.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/11/06/4");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14472");
  script_xref(name:"URL", value:"https://polarssl.org/tech-updates/releases/polarssl-1.3.9-released");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'polarssl' package(s) announced via the MGASA-2014-0481 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A regression in PolarSSL 1.3.8 resulted in servers negotiating a weaker
signature algorithm than available. This has been fixed in PolarSSL 1.3.9
(CVE-2014-8627).

Two remotely-triggerable memory leaks were found by the Codenomicon Defensics
tool and fixed in PolarSSL 1.3.9 (CVE-2014-8628).");

  script_tag(name:"affected", value:"'polarssl' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64polarssl-devel", rpm:"lib64polarssl-devel~1.3.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polarssl7", rpm:"lib64polarssl7~1.3.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolarssl-devel", rpm:"libpolarssl-devel~1.3.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolarssl7", rpm:"libpolarssl7~1.3.9~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polarssl", rpm:"polarssl~1.3.9~1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64polarssl-devel", rpm:"lib64polarssl-devel~1.3.9~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polarssl7", rpm:"lib64polarssl7~1.3.9~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolarssl-devel", rpm:"libpolarssl-devel~1.3.9~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolarssl7", rpm:"libpolarssl7~1.3.9~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polarssl", rpm:"polarssl~1.3.9~1.mga4", rls:"MAGEIA4"))) {
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
