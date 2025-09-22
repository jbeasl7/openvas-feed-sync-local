# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00047.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870690");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-07-09 10:47:29 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-4862");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2011:1852-02");
  script_name("RedHat Update for krb5-appl RHSA-2011:1852-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5-appl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"krb5-appl on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The krb5-appl packages provide Kerberos-aware telnet, ftp, rcp, rsh, and
  rlogin clients and servers. Kerberos is a network authentication system
  which allows clients and servers to authenticate to each other using
  symmetric encryption and a trusted third-party, the Key Distribution Center
  (KDC).

  A buffer overflow flaw was found in the MIT krb5 telnet daemon
  (telnetd). A remote attacker who can access the telnet port of a
  target machine could use this flaw to execute arbitrary code as
  root. (CVE-2011-4862)

  Note that the krb5 telnet daemon is not enabled by default in any
  version of Red Hat Enterprise Linux. In addition, the default firewall
  rules block remote access to the telnet port. This flaw does not
  affect the telnet daemon distributed in the telnet-server package.

  For users who have installed the krb5-appl-servers package, have
  enabled the krb5 telnet daemon, and have it accessible remotely, this
  update should be applied immediately.

  All krb5-appl-server users should upgrade to these updated packages,
  which contain a backported patch to correct this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"krb5-appl-clients", rpm:"krb5-appl-clients~1.0.1~7.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-appl-debuginfo", rpm:"krb5-appl-debuginfo~1.0.1~7.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-appl-servers", rpm:"krb5-appl-servers~1.0.1~7.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
