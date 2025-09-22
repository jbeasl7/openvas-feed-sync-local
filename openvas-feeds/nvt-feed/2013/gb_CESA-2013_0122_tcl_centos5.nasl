# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019168.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881574");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-21 09:41:48 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2007-4772", "CVE-2007-6067");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_xref(name:"CESA", value:"2013:0122");
  script_name("CentOS Update for tcl CESA-2013:0122 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"tcl on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Tcl (Tool Command Language) provides a powerful platform for creating
  integration applications that tie together diverse applications, protocols,
  devices, and frameworks. When paired with the Tk toolkit, Tcl provides a
  fast and powerful way to create cross-platform GUI applications.

  Two denial of service flaws were found in the Tcl regular expression
  handling engine. If Tcl or an application using Tcl processed a
  specially-crafted regular expression, it would lead to excessive CPU and
  memory consumption. (CVE-2007-4772, CVE-2007-6067)

  This update also fixes the following bug:

  * Due to a suboptimal implementation of threading in the current version of
  the Tcl language interpreter, an attempt to use threads in combination with
  fork in a Tcl script could cause the script to stop responding. At the
  moment, it is not possible to rewrite the source code or drop support for
  threading entirely. Consequent to this, this update provides a version of
  Tcl without threading support in addition to the standard version with this
  support. Users who need to use fork in their Tcl scripts and do not require
  threading can now switch to the version without threading support by using
  the alternatives command. (BZ#478961)

  All users of Tcl are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"tcl", rpm:"tcl~8.4.13~6.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcl-devel", rpm:"tcl-devel~8.4.13~6.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcl-html", rpm:"tcl-html~8.4.13~6.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
