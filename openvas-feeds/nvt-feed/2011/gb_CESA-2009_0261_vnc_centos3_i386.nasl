# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-February/015629.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880800");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:0261");
  script_cve_id("CVE-2008-4770");
  script_name("CentOS Update for vnc CESA-2009:0261 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vnc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"vnc on CentOS 3");
  script_tag(name:"insight", value:"Virtual Network Computing (VNC) is a remote display system which allows you
  to view a computer's 'desktop' environment not only on the machine where it
  is running, but from anywhere on the Internet and from a wide variety of
  machine architectures.

  An insufficient input validation flaw was discovered in the VNC client
  application, vncviewer. If an attacker could convince a victim to connect
  to a malicious VNC server, or when an attacker was able to connect to
  vncviewer running in the 'listen' mode, the attacker could cause the
  victim's vncviewer to crash or, possibly, execute arbitrary code.
  (CVE-2008-4770)

  Users of vncviewer should upgrade to these updated packages, which contain
  a backported patch to resolve this issue. For the update to take effect,
  all running instances of vncviewer must be restarted after the update is
  installed.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"vnc", rpm:"vnc~4.0~0.beta4.1.8", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vnc-server", rpm:"vnc-server~4.0~0.beta4.1.8", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
