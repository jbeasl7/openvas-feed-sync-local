# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0245");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2016-0245)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0245");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0245.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18806");
  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2016-002");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.44");
  script_xref(name:"URL", value:"https://www.drupal.org/drupal-7.44-release-notes");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal' package(s) announced via the MGASA-2016-0245 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated drupal packages fix security vulnerability:

A vulnerability exists in the User module, where if some specific contributed
or custom code triggers a rebuild of the user profile form, a registered user
can be granted all user roles on the site. This would typically result in the
user gaining administrative access (SA-CORE-2016-002).");

  script_tag(name:"affected", value:"'drupal' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"drupal", rpm:"drupal~7.44~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-mysql", rpm:"drupal-mysql~7.44~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-postgresql", rpm:"drupal-postgresql~7.44~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-sqlite", rpm:"drupal-sqlite~7.44~1.mga5", rls:"MAGEIA5"))) {
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
