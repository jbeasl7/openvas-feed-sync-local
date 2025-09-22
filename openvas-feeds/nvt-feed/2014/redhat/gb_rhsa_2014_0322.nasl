# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871145");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-03-25 10:25:21 +0530 (Tue, 25 Mar 2014)");
  script_cve_id("CVE-2012-6151", "CVE-2014-2285");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for net-snmp RHSA-2014:0322-01");


  script_tag(name:"affected", value:"net-snmp on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"The net-snmp packages provide various libraries and tools for the Simple
Network Management Protocol (SNMP), including an SNMP library, an
extensible agent, tools for requesting or setting information from SNMP
agents, tools for generating and handling SNMP traps, a version of the
netstat command which uses SNMP, and a Tk/Perl Management Information Base
(MIB) browser.

A denial of service flaw was found in the way snmpd, the Net-SNMP daemon,
handled subagent timeouts. A remote attacker able to trigger a subagent
timeout could use this flaw to cause snmpd to loop infinitely or crash.
(CVE-2012-6151)

A denial of service flaw was found in the way the snmptrapd service, which
receives and logs SNMP trap messages, handled SNMP trap requests with an
empty community string when the Perl handler (provided by the net-snmp-perl
package) was enabled. A remote attacker could use this flaw to crash
snmptrapd by sending a trap request with an empty community string.
(CVE-2014-2285)

All net-snmp users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, the snmpd and snmptrapd services will be restarted automatically.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:0322-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-March/msg00031.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.2.2~22.el5_10.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.3.2.2~22.el5_10.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.2.2~22.el5_10.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.3.2.2~22.el5_10.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.3.2.2~22.el5_10.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.3.2.2~22.el5_10.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}