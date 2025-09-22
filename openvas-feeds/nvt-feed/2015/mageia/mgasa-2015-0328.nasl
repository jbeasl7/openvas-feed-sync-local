# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130056");
  script_cve_id("CVE-2015-6658", "CVE-2015-6659", "CVE-2015-6660", "CVE-2015-6661", "CVE-2015-6665");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:08 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0328)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0328");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0328.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16630");
  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2015-003");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.39");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.39-release-notes");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal' package(s) announced via the MGASA-2015-0328 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting (XSS) vulnerability in the Autocomplete system in Drupal
before 7.39 allows remote attackers to inject arbitrary web script or HTML
via a crafted URL, related to uploading files (CVE-2015-6658).

SQL injection vulnerability in the SQL comment filtering system in the
Database API in Drupal before 7.39 allows remote attackers to execute
arbitrary SQL commands via an SQL comment (CVE-2015-6659).

The Form API in Drupal 6.x before 6.37 and 7.x before 7.39 does not properly
validate the form token, which allows remote attackers to conduct CSRF
attacks that upload files in a different user's account via vectors related
to 'file upload value callbacks' (CVE-2015-6660).

Drupal before 7.39 allows remote attackers to obtain sensitive node titles by
reading the menu (CVE-2015-6661).

Cross-site scripting (XSS) vulnerability in the Ajax handler in Drupal before
7.39 allows remote attackers to inject arbitrary web script or HTML via
vectors involving a whitelisted HTML element, possibly related to the 'a' tag
(CVE-2015-6665).");

  script_tag(name:"affected", value:"'drupal' package(s) on Mageia 4, Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"drupal", rpm:"drupal~7.39~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-mysql", rpm:"drupal-mysql~7.39~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-postgresql", rpm:"drupal-postgresql~7.39~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-sqlite", rpm:"drupal-sqlite~7.39~1.mga4", rls:"MAGEIA4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"drupal", rpm:"drupal~7.39~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-mysql", rpm:"drupal-mysql~7.39~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-postgresql", rpm:"drupal-postgresql~7.39~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-sqlite", rpm:"drupal-sqlite~7.39~1.mga5", rls:"MAGEIA5"))) {
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
