# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.873180");
  script_version("2023-06-29T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-29 05:05:23 +0000 (Thu, 29 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:40 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2017-7018", "CVE-2017-7030", "CVE-2017-7034", "CVE-2017-7037",
                "CVE-2017-7039", "CVE-2017-7046", "CVE-2017-7048", "CVE-2017-7055",
                "CVE-2017-7056", "CVE-2017-7061", "CVE-2017-7064");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-22 19:22:00 +0000 (Fri, 22 Mar 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for webkitgtk4 FEDORA-2017-24bddb96b5");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkitgtk4'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"webkitgtk4 on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2017-24bddb96b5");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5WQG4TVFXCPDMB3M6X46ISBMRZAHJZ43");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC26");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"webkitgtk4", rpm:"webkitgtk4~2.16.6~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
