# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871429");
  script_version("2024-03-21T05:06:54+0000");
  script_cve_id("CVE-2015-5621");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-08-18 06:48:55 +0200 (Tue, 18 Aug 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for net-snmp RHSA-2015:1636-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The net-snmp packages provide various libraries and tools for the Simple
Network Management Protocol (SNMP), including an SNMP library, an
extensible agent, tools for requesting or setting information from SNMP
agents, tools for generating and handling SNMP traps, a version of the
netstat command which uses SNMP, and a Tk/Perl Management Information Base
(MIB) browser.

It was discovered that the snmp_pdu_parse() function could leave
incompletely parsed varBind variables in the list of variables. A remote,
unauthenticated attacker could use this flaw to crash snmpd or,
potentially, execute arbitrary code on the system with the privileges of
the user running snmpd. (CVE-2015-5621)

Red Hat would like to thank Qinghao Tang of QIHU 360 company, China for
reporting this issue.

All net-snmp users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue.");
  script_tag(name:"affected", value:"net-snmp on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1636-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-August/msg00029.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.2~20.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-agent-libs", rpm:"net-snmp-agent-libs~5.7.2~20.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.7.2~20.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.7.2~20.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.7.2~20.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.7.2~20.el7_1.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.5~54.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.5~54.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.5~54.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.5~54.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.5~54.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-python", rpm:"net-snmp-python~5.5~54.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.5~54.el6_7.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
