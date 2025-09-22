# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-December/018360.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881380");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:37:55 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-4862");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:1851");
  script_name("CentOS Update for krb5-devel CESA-2011:1851 centos4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5-devel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"krb5-devel on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other using symmetric encryption and a
  trusted third- party, the Key Distribution Center (KDC).

  A buffer overflow flaw was found in the MIT krb5 telnet daemon
  (telnetd). A remote attacker who can access the telnet port of a
  target machine could use this flaw to execute arbitrary code as
  root. (CVE-2011-4862)

  Note that the krb5 telnet daemon is not enabled by default in any
  version of Red Hat Enterprise Linux. In addition, the default firewall
  rules block remote access to the telnet port. This flaw does not
  affect the telnet daemon distributed in the telnet-server package.

  For users who have installed the krb5-workstation package, have
  enabled the telnet daemon, and have it accessible remotely, this
  update should be applied immediately.

  All krb5-workstation users should upgrade to these updated packages,
  which contain a backported patch to correct this issue.");
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

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.3.4~65.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.3.4~65.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.3.4~65.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.3.4~65.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.3.4~65.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
