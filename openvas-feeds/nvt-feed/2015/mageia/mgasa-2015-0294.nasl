# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130084");
  script_cve_id("CVE-2015-3192");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:31 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-12 21:43:49 +0000 (Tue, 12 Jul 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0294)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0294");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0294.html");
  script_xref(name:"URL", value:"http://pivotal.io/security/cve-2015-3192");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16394");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'springframework' package(s) announced via the MGASA-2015-0294 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Spring Framework before 3.2.14, if DTD is not entirely disabled, inline
DTD declarations can be used to perform denial of service attacks known as
XML bombs. Such declarations are both well-formed and valid according to
XML schema rules but when parsed can cause out of memory errors. To
protect against this kind of attack DTD support must be disabled by
setting the disallow-doctype-dec feature in the DOM and SAX APIs to true
and by setting the supportDTD property in the StAX API to false
(CVE-2015-3192).

This package is no longer supported for Mageia 4. Users of this package
are advised to upgrade to Mageia 5");

  script_tag(name:"affected", value:"'springframework' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"springframework", rpm:"springframework~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-aop", rpm:"springframework-aop~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-beans", rpm:"springframework-beans~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-context", rpm:"springframework-context~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-context-support", rpm:"springframework-context-support~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-expression", rpm:"springframework-expression~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-instrument", rpm:"springframework-instrument~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-instrument-tomcat", rpm:"springframework-instrument-tomcat~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-javadoc", rpm:"springframework-javadoc~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-jdbc", rpm:"springframework-jdbc~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-jms", rpm:"springframework-jms~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-orm", rpm:"springframework-orm~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-oxm", rpm:"springframework-oxm~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-struts", rpm:"springframework-struts~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-test", rpm:"springframework-test~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-tx", rpm:"springframework-tx~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-web", rpm:"springframework-web~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-webmvc", rpm:"springframework-webmvc~3.2.14~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"springframework-webmvc-portlet", rpm:"springframework-webmvc-portlet~3.2.14~1.mga5", rls:"MAGEIA5"))) {
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
