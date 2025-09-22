# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019670.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881699");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-03-28 09:49:44 +0530 (Thu, 28 Mar 2013)");
  script_cve_id("CVE-2013-1591");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 21:08:00 +0000 (Thu, 15 Feb 2024)");
  script_xref(name:"CESA", value:"2013:0687");
  script_name("CentOS Update for pixman CESA-2013:0687 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pixman'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"pixman on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Pixman is a pixel manipulation library for the X Window System and Cairo.

  An integer overflow flaw was discovered in one of pixman's manipulation
  routines. If a remote attacker could trick an application using pixman into
  performing a certain manipulation, it could cause the application to crash
  or, possibly, execute arbitrary code with the privileges of the user
  running the application. (CVE-2013-1591)

  Users are advised to upgrade to these updated packages, which contain
  a backported patch to correct this issue. All applications using
  pixman must be restarted for this update to take effect.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"pixman", rpm:"pixman~0.26.2~5.0.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pixman-devel", rpm:"pixman-devel~0.26.2~5.0.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
