# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.872684");
  script_version("2023-06-30T05:06:12+0000");
  script_tag(name:"last_modification", value:"2023-06-30 05:06:12 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-05-18 06:59:04 +0200 (Thu, 18 May 2017)");
  script_cve_id("CVE-2016-10369", "CVE-2017-8933", "CVE-2017-8934");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-16 18:41:00 +0000 (Tue, 16 May 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for menu-cache FEDORA-2017-6950ea5d05");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'menu-cache'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"menu-cache on Fedora 25");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2017-6950ea5d05");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NYIR73RHZNAQMVWRG2Y6GXPP5TK2KDN3");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC25");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"menu-cache", rpm:"menu-cache~1.0.2~4.D20170514git56f6668459.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
