# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019606.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881630");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-12 09:58:43 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2011-2504");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2013:0502");
  script_name("CentOS Update for xorg-x11-utils CESA-2013:0502 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"xorg-x11-utils on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The Core X11 clients packages provide the xorg-x11-utils,
  xorg-x11-server-utils, and xorg-x11-apps clients that ship with the X
  Window System.

  It was found that the x11perfcomp utility included the current working
  directory in its PATH environment variable. Running x11perfcomp in an
  attacker-controlled directory would cause arbitrary code execution with
  the privileges of the user running x11perfcomp. (CVE-2011-2504)

  Also with this update, the xorg-x11-utils and xorg-x11-server-utils
  packages have been upgraded to upstream version 7.5, and the xorg-x11-apps
  package to upstream version 7.6, which provides a number of bug fixes and
  enhancements over the previous versions. (BZ#835277, BZ#835278, BZ#835281)

  All users of xorg-x11-utils, xorg-x11-server-utils, and xorg-x11-apps are
  advised to upgrade to these updated packages, which fix these issues and
  add these enhancements.");
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

  if ((res = isrpmvuln(pkg:"xorg-x11-utils", rpm:"xorg-x11-utils~7.5~6.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
