# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.877101");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2020-01-08 11:19:40 +0000 (Wed, 08 Jan 2020)");
  script_name("Fedora Update for drupal7-webform FEDORA-2019-6abe00cae1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2019-6abe00cae1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6QP5IQ7VXCZWFUF4IRWIFX7WXQZQ7DN5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal7-webform'
  package(s) announced via the FEDORA-2019-6abe00cae1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Webform is the module for making forms and surveys in Drupal. After a
submission, users may be sent an e-mail 'receipt' as well as sending a
notification to administrators. Results can be exported into Excel or
other spreadsheet applications. Webform also provides some basic statistical
review and has an extensive API for expanding its features.

Some good examples could be contests, personalized contact forms, or petitions.
Each of these could have a customized form for end-users to fill out. If you
need to build a lot of customized, one-off forms, Webform is a more suitable
solution than creating content types and using CCK or Field module. Explanation
of Webform vs. CCK (or Fields) [1].

This package provides the following Drupal 7 module:

  * webform");

  script_tag(name:"affected", value:"'drupal7-webform' package(s) on Fedora 30.");

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

if(release == "FC30") {

  if(!isnull(res = isrpmvuln(pkg:"drupal7-webform", rpm:"drupal7-webform~4.21~1.fc30", rls:"FC30"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
