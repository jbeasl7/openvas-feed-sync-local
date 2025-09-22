# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870887");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:45 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2011-4966");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2013:0134-01");
  script_name("RedHat Update for freeradius2 RHSA-2013:0134-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"freeradius2 on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"FreeRADIUS is an open-source Remote Authentication Dial-In User Service
  (RADIUS) server which allows RADIUS clients to perform authentication
  against the RADIUS server. The RADIUS server may optionally perform
  accounting of its operations using the RADIUS protocol.

  It was found that the 'unix' module ignored the password expiration
  setting in '/etc/shadow'. If FreeRADIUS was configured to use this module
  for user authentication, this flaw could allow users with an expired
  password to successfully authenticate, even though their access should have
  been denied. (CVE-2011-4966)

  This update also fixes the following bugs:

  * After log rotation, the freeradius logrotate script failed to reload the
  radiusd daemon and log messages were lost. This update has added a command
  to the freeradius logrotate script to reload the radiusd daemon and the
  radiusd daemon re-initializes and reopens its log files after log rotation
  as expected. (BZ#787111)

  * The radtest script with the 'eap-md5' option failed because it passed the
  IP family argument when invoking the radeapclient utility and the
  radeapclient utility did not recognize the IP family. The radeapclient
  utility now recognizes the IP family argument and radtest now works with
  eap-md5 as expected. (BZ#846476)

  * Previously, freeradius was compiled without the '--with-udpfromto'
  option. Consequently, with a multihomed server and explicitly specifying
  the IP address, freeradius sent the reply with the wrong IP source address.
  With this update, freeradius has been built with the '--with-udpfromto&quot'
  configuration option and the RADIUS reply is always sourced from the IP
  address the request was sent to. (BZ#846471)

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

  if ((res = isrpmvuln(pkg:"freeradius2", rpm:"freeradius2~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-debuginfo", rpm:"freeradius2-debuginfo~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-krb5", rpm:"freeradius2-krb5~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-ldap", rpm:"freeradius2-ldap~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-mysql", rpm:"freeradius2-mysql~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-perl", rpm:"freeradius2-perl~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-postgresql", rpm:"freeradius2-postgresql~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-python", rpm:"freeradius2-python~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-unixODBC", rpm:"freeradius2-unixODBC~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-utils", rpm:"freeradius2-utils~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
