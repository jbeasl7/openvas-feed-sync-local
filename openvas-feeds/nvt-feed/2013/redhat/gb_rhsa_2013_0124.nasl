# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00007.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870877");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-01-11 16:41:41 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2012-2141");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2013:0124-01");
  script_name("RedHat Update for net-snmp RHSA-2013:0124-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"net-snmp on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"These packages provide various libraries and tools for the Simple Network
  Management Protocol (SNMP).

  An out-of-bounds buffer read flaw was found in the net-snmp agent. A remote
  attacker with read privileges to a Management Information Base (MIB)
  subtree handled by the extend directive (/etc/snmp/snmpd.conf)
  could use this flaw to crash snmpd via a crafted SNMP GET request.
  (CVE-2012-2141)

  Bug fixes:

  * Devices that used certain file systems were not reported in the
  'HOST-RESOURCES-MIB::hrStorageTable' table. As a result, the snmpd daemon
  did not recognize devices using tmpfs, ReiserFS, and Oracle Cluster File
  System (OCFS2) file systems. This update recognizes these devices and
  reports them in the 'HOST-RESOURCES-MIB::hrStorageTable' table.
  (BZ#754652, BZ#755958, BZ#822061)

  * The snmptrapd (8) man page did not correctly describe how to load
  multiple configuration files using the '-c' option. This update describes
  correctly that multiple configuration files must be separated by a comma.
  (BZ#760001)

  * Integers truncated from 64 to 32-bit were not correctly evaluated. As a
  consequence, the snmpd daemon could enter an endless loop when encoding the
  truncated integers to network format. This update modifies the underlying
  code so that snmpd correctly checks truncated 64-bit integers. Now, snmpd
  avoids an endless loop. (BZ#783892)

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.2.2~20.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.3.2.2~20.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.2.2~20.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.3.2.2~20.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.3.2.2~20.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.3.2.2~20.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
