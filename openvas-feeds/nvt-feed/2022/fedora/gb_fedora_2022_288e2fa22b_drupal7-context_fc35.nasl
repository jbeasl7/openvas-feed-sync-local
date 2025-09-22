# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.822886");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-11-24 02:16:39 +0000 (Thu, 24 Nov 2022)");
  script_name("Fedora: Security Advisory for drupal7-context (FEDORA-2022-288e2fa22b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-288e2fa22b");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YAIJISQWCQAGLDKS2JC3AMJ4UJEUKCJN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal7-context'
  package(s) announced via the FEDORA-2022-288e2fa22b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Context allows you to manage contextual conditions and reactions for different
portions of your site. You can think of each context as representing a
'section'
of your site. For each context, you can choose the conditions that trigger this
context to be active and choose different aspects of Drupal that should react to
this active context.

Think of conditions as a set of rules that are checked during page load to see
what context is active. Any reactions that are associated with active contexts
are then fired.

This package provides the following Drupal modules:

  * context

  * context_layouts

  * context_ui");

  script_tag(name:"affected", value:"'drupal7-context' package(s) on Fedora 35.");

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

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"drupal7-context", rpm:"drupal7-context~3.11~1.fc35", rls:"FC35"))) {
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
