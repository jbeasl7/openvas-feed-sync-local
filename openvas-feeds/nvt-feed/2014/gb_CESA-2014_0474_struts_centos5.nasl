# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881933");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-05-12 09:12:02 +0530 (Mon, 12 May 2014)");
  script_cve_id("CVE-2014-0114");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for struts CESA-2014:0474 centos5");

  script_tag(name:"affected", value:"struts on CentOS 5");
  script_tag(name:"insight", value:"Apache Struts is a framework for building web applications
with Java.

It was found that the Struts 1 ActionForm object allowed access to the
'class' parameter, which is directly mapped to the getClass() method. A
remote attacker could use this flaw to manipulate the ClassLoader used by
an application server running Struts 1. This could lead to remote code
execution under certain conditions. (CVE-2014-0114)

All struts users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. All running applications
using struts must be restarted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0474");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-May/020284.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'struts'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"struts", rpm:"struts~1.2.9~4jpp.8.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"struts-javadoc", rpm:"struts-javadoc~1.2.9~4jpp.8.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"struts-manual", rpm:"struts-manual~1.2.9~4jpp.8.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"struts-webapps-tomcat5", rpm:"struts-webapps-tomcat5~1.2.9~4jpp.8.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
