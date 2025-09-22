# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881852");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-23 12:46:09 +0530 (Mon, 23 Dec 2013)");
  script_cve_id("CVE-2013-6425");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for pixman CESA-2013:1869 centos5");

  script_tag(name:"affected", value:"pixman on CentOS 5");
  script_tag(name:"insight", value:"Pixman is a pixel manipulation library for the X Window System and Cairo.

An integer overflow, which led to a heap-based buffer overflow, was found
in the way pixman handled trapezoids. If a remote attacker could trick an
application using pixman into rendering a trapezoid shape with specially
crafted coordinates, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2013-6425)

Users are advised to upgrade to these updated packages, which contain a
backported patch to correct this issue. All applications using pixman
must be restarted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1869");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-December/020091.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'pixman'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"pixman", rpm:"pixman~0.22.0~2.2.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pixman-devel", rpm:"pixman-devel~0.22.0~2.2.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
