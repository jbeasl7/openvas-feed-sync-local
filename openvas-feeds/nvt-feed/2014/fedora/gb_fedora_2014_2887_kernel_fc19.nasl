# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.867546");
  script_version("2023-06-23T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-23 16:09:17 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2014-03-04 10:32:46 +0530 (Tue, 04 Mar 2014)");
  script_cve_id("CVE-2014-2039", "CVE-2014-0069", "CVE-2014-1874", "CVE-2014-1446",
                "CVE-2014-1438", "CVE-2013-4579", "CVE-2013-4587", "CVE-2013-6376",
                "CVE-2013-6368", "CVE-2013-6367", "CVE-2013-6405", "CVE-2013-6382",
                "CVE-2013-6380", "CVE-2013-6378", "CVE-2013-4563", "CVE-2013-4348",
                "CVE-2013-4470", "CVE-2013-4387", "CVE-2013-4345", "CVE-2013-4350",
                "CVE-2013-4343", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2891",
                "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2894", "CVE-2013-2895",
                "CVE-2013-2896", "CVE-2013-2897", "CVE-2013-2899", "CVE-2013-0343",
                "CVE-2013-4254", "CVE-2013-4125", "CVE-2013-2232", "CVE-2013-1059",
                "CVE-2013-2234");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Fedora Update for kernel FEDORA-2014-2887");
  script_tag(name:"affected", value:"kernel on Fedora 19");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"FEDORA", value:"2014-2887");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-March/129241.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.13.5~101.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
