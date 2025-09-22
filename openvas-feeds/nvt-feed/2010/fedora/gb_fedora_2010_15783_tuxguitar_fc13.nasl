# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049697.html");
  script_oid("1.3.6.1.4.1.25623.1.0.862459");
  script_version("2023-06-30T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-30 16:09:17 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-10-22 16:42:09 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"FEDORA", value:"2010-15783");
  script_cve_id("CVE-2010-3385");
  script_name("Fedora Update for tuxguitar FEDORA-2010-15783");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tuxguitar'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC13");
  script_tag(name:"affected", value:"tuxguitar on Fedora 13");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC13")
{

  if ((res = isrpmvuln(pkg:"tuxguitar", rpm:"tuxguitar~1.2~3.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
