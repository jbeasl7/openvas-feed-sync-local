# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-January/016433.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880595");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name:"CESA", value:"2010:0018");
  script_cve_id("CVE-2009-1189", "CVE-2008-3834");
  script_name("CentOS Update for dbus CESA-2010:0018 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"dbus on CentOS 5");
  script_tag(name:"insight", value:"D-Bus is a system for sending messages between applications. It is used for
  the system-wide message bus service and as a per-user-login-session
  messaging facility.

  It was discovered that the Red Hat Security Advisory RHSA-2009:0008 did
  not correctly fix the denial of service flaw in the system for sending
  messages between applications. A local user could use this flaw to send a
  message with a malformed signature to the bus, causing the bus (and,
  consequently, any process using libdbus to receive messages) to abort.
  (CVE-2009-1189)

  Note: Users running any application providing services over the system
  message bus are advised to test this update carefully before deploying it
  in production environments.

  All users are advised to upgrade to these updated packages, which contain a
  backported patch to correct this issue. For the update to take effect, all
  running instances of dbus-daemon and all running applications using the
  libdbus library must be restarted, or the system rebooted.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.1.2~12.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-devel", rpm:"dbus-devel~1.1.2~12.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-libs", rpm:"dbus-libs~1.1.2~12.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.1.2~12.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
