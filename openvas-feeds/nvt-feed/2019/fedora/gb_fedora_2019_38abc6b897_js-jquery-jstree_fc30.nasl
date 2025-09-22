# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.876496");
  script_version("2025-04-24T05:40:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:00 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2019-06-14 02:10:35 +0000 (Fri, 14 Jun 2019)");
  script_name("Fedora Update for js-jquery-jstree FEDORA-2019-38abc6b897");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2019-38abc6b897");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/53YZIQ5TE2P3JXULG6QPK27Z7O2KB2G6");

  script_tag(name:"summary", value:"The remote host is missing an update for
  the 'js-jquery-jstree' package(s) announced via the FEDORA-2019-38abc6b897
  advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version
  is present on the target host.");

  script_tag(name:"insight", value:"jsTree is jquery plugin, that provides
  interactive trees. It is absolutely free, open source and distributed under the
  MIT license.

jsTree is easily extendable, themable and configurable, it supports HTML
& JSON data sources, AJAX & async callback loading.

jsTree functions properly in either box-model (content-box or
border-box), can be loaded as an AMD module, and has a built in mobile
theme for responsive design, that can easily be customized. It uses
jQuery&#39, s event system, so binding callbacks on various events in the
tree is familiar and easy.");

  script_tag(name:"affected", value:"'js-jquery-jstree' package(s) on Fedora 30.");

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

  if(!isnull(res = isrpmvuln(pkg:"js-jquery-jstree", rpm:"js-jquery-jstree~3.3.8~1.fc30", rls:"FC30"))) {
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
