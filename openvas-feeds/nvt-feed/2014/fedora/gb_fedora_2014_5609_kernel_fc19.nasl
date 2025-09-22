# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.867774");
  script_version("2023-06-23T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-06-23 05:05:08 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2014-05-12 09:07:31 +0530 (Mon, 12 May 2014)");
  script_cve_id("CVE-2014-2851", "CVE-2014-0155", "CVE-2014-2678", "CVE-2014-2580",
                "CVE-2014-0077", "CVE-2014-0055", "CVE-2014-2568", "CVE-2014-0131",
                "CVE-2014-2523", "CVE-2014-2309", "CVE-2014-0100", "CVE-2014-0101",
                "CVE-2014-0049", "CVE-2014-0102", "CVE-2014-2039", "CVE-2014-0069",
                "CVE-2014-1874", "CVE-2014-1446", "CVE-2014-1438", "CVE-2013-4579",
                "CVE-2013-4587", "CVE-2013-6376", "CVE-2013-6368", "CVE-2013-6367",
                "CVE-2013-6405", "CVE-2013-6382", "CVE-2013-6380", "CVE-2013-6378",
                "CVE-2013-4563", "CVE-2013-4348", "CVE-2013-4470", "CVE-2013-4387",
                "CVE-2013-4345", "CVE-2013-4350", "CVE-2013-4343", "CVE-2013-2888",
                "CVE-2013-2889", "CVE-2013-2891", "CVE-2013-2892", "CVE-2013-2893",
                "CVE-2013-2894", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897",
                "CVE-2013-2899", "CVE-2013-0343", "CVE-2013-4254", "CVE-2013-4125",
                "CVE-2013-2232", "CVE-2013-1059", "CVE-2013-2234");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Update for kernel FEDORA-2014-5609");
  script_tag(name:"affected", value:"kernel on Fedora 19");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"FEDORA", value:"2014-5609");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-May/132577.html");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.13.11~100.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
