# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.865593");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2013-05-03 09:53:26 +0530 (Fri, 03 May 2013)");
  script_cve_id("CVE-2013-3228", "CVE-2013-3230", "CVE-2013-3231", "CVE-2013-3232",
                "CVE-2013-3233", "CVE-2013-3234", "CVE-2013-3076", "CVE-2013-3223",
                "CVE-2013-3225", "CVE-2013-1979", "CVE-2013-3224", "CVE-2013-3222",
                "CVE-2013-1929", "CVE-2013-1873", "CVE-2013-1796", "CVE-2013-1797",
                "CVE-2013-1798", "CVE-2013-1860", "CVE-2013-0913", "CVE-2013-0914",
                "CVE-2013-1828", "CVE-2013-1792", "CVE-2013-1767", "CVE-2013-1763",
                "CVE-2013-0290", "CVE-2013-0228", "CVE-2013-0190");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Update for kernel FEDORA-2013-6537");
  script_xref(name:"FEDORA", value:"2013-6537");
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-April/103750.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC18");
  script_tag(name:"affected", value:"kernel on Fedora 18");
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

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.8.8~203.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
