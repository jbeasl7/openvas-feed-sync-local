# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871021");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-05-20 12:45:14 +0530 (Tue, 20 May 2014)");
  script_cve_id("CVE-2013-2219");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_name("RedHat Update for 389-ds-base RHSA-2013:1119-01");


  script_tag(name:"affected", value:"389-ds-base on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"The 389 Directory Server is an LDAPv3 compliant server. The base packages
include the Lightweight Directory Access Protocol (LDAP) server and
command-line utilities for server administration.

It was discovered that the 389 Directory Server did not honor defined
attribute access controls when evaluating search filter expressions. A
remote attacker (with permission to query the Directory Server) could use
this flaw to determine the values of restricted attributes via a series of
search queries with filter conditions that used restricted attributes.
(CVE-2013-2219)

This issue was discovered by Ludwig Krispenz of Red Hat.

This update also fixes the following bugs:

  * Previously, the disk monitoring feature did not function properly. If
logging functionality was set to critical and logging was disabled, rotated
logs would be deleted. If the attribute 'nsslapd-errorlog-level' was
explicitly set to any value, even zero, the disk monitoring feature would
not stop the Directory Server when it was supposed to. This update
corrects the disk monitoring feature settings, and it no longer
malfunctions in the described scenarios. (BZ#972930)

  * Previously, setting the 'nsslapd-disk-monitoring-threshold' attribute via
ldapmodify to a large value worked as expected  however, a bug in
ldapsearch caused such values for the option to be displayed as negative
values. This update corrects the bug in ldapsearch and correct values are
now displayed. (BZ#984970)

  * If logging functionality was not set to critical, then the mount point
for the logs directory was incorrectly skipped during the disk space check.
(BZ#987850)

All 389-ds-base users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After installing
this update, the 389 server service will be restarted automatically.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2013:1119-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-July/msg00035.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.11.15~20.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-debuginfo", rpm:"389-ds-base-debuginfo~1.2.11.15~20.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.11.15~20.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
