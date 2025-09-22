# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.867506");
  script_version("2023-06-23T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-06-23 05:05:08 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2014-02-17 11:36:58 +0530 (Mon, 17 Feb 2014)");
  script_cve_id("CVE-2014-1666", "CVE-2014-1642", "CVE-2013-6400", "CVE-2013-6885",
                "CVE-2013-4553", "CVE-2013-4554", "CVE-2013-6375", "CVE-2013-4551",
                "CVE-2013-4494", "CVE-2013-4416", "CVE-2013-4368", "CVE-2013-4369",
                "CVE-2013-4370", "CVE-2013-4371", "CVE-2013-4375", "CVE-2013-4355",
                "CVE-2013-4361", "CVE-2013-1442", "CVE-2013-4329", "CVE-2013-1918",
                "CVE-2013-1432", "CVE-2013-2211", "CVE-2013-2194", "CVE-2013-2195",
                "CVE-2013-2196", "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893",
                "CVE-2014-1894", "CVE-2014-1895", "CVE-2014-1896");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Update for xen FEDORA-2014-2188");
  script_tag(name:"affected", value:"xen on Fedora 19");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"FEDORA", value:"2014-2188");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-February/128429.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC19");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.3~15.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
