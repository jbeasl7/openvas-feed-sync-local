# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-January/015549.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880922");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:0018");
  script_cve_id("CVE-2008-2383");
  script_name("CentOS Update for xterm-192-8.el4 CESA-2009:0018 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xterm-192-8.el4'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"xterm-192-8.el4_ on CentOS 4");
  script_tag(name:"insight", value:"The xterm program is a terminal emulator for the X Window System.

  A flaw was found in the xterm handling of Device Control Request Status
  String (DECRQSS) escape sequences. An attacker could create a malicious
  text file (or log entry, if unfiltered) that could run arbitrary commands
  if read by a victim inside an xterm window. (CVE-2008-2383)

  All xterm users are advised to upgrade to the updated package, which
  contains a backported patch to resolve this issue. All running instances of
  xterm must be restarted for the update to take effect.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"xterm", rpm:"xterm~192~8.el4_7.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
