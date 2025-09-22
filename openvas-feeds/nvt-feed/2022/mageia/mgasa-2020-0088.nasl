# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0088");
  script_cve_id("CVE-2019-16865", "CVE-2019-19911", "CVE-2020-5310", "CVE-2020-5311", "CVE-2020-5312", "CVE-2020-5313");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-10 17:09:14 +0000 (Fri, 10 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0088)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0088");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0088.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25968");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4272-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pillow' package(s) announced via the MGASA-2020-0088 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-pillow packages fix security vulnerabilities:

It was discovered that Pillow incorrectly handled certain images. An attacker
could possibly use this issue to cause a denial of service (CVE-2019-16865,
CVE-2019-19911).

It was discovered that Pillow incorrectly handled certain TIFF images. An
attacker could possibly use this issue to cause a crash (CVE-2020-5310).

It was discovered that Pillow incorrectly handled certain SGI images. An
attacker could possibly use this issue to execute arbitrary code or cause
a crash (CVE-2020-5311).

It was discovered that Pillow incorrectly handled certain PCX images. An
attacker could possibly use this issue to execute arbitrary code or cause
a crash (CVE-2020-5312).

It was discovered that Pillow incorrectly handled certain Flip images. An
attacker could possibly use this issue to execute arbitrary code or cause
a crash (CVE-2020-5313).");

  script_tag(name:"affected", value:"'python-pillow' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"python-pillow", rpm:"python-pillow~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pillow", rpm:"python2-pillow~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pillow-devel", rpm:"python2-pillow-devel~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pillow-doc", rpm:"python2-pillow-doc~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pillow-qt", rpm:"python2-pillow-qt~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pillow-tk", rpm:"python2-pillow-tk~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow", rpm:"python3-pillow~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-devel", rpm:"python3-pillow-devel~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-doc", rpm:"python3-pillow-doc~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-qt", rpm:"python3-pillow-qt~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-tk", rpm:"python3-pillow-tk~5.4.1~1.1.mga7", rls:"MAGEIA7"))) {
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
