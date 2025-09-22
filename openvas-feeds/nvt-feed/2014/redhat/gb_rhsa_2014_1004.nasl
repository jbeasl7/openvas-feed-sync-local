# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871215");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-08-05 16:51:28 +0530 (Tue, 05 Aug 2014)");
  script_cve_id("CVE-2014-0022");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("RedHat Update for yum-updatesd RHSA-2014:1004-01");


  script_tag(name:"affected", value:"yum-updatesd on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"The yum-updatesd package provides a daemon which checks for available
updates and can notify you when they are available via email, syslog,
or dbus.

It was discovered that yum-updatesd did not properly perform RPM package
signature checks. When yum-updatesd was configured to automatically install
updates, a remote attacker could use this flaw to install a malicious
update on the target system using an unsigned RPM or an RPM signed with an
untrusted key. (CVE-2014-0022)

All yum-updatesd users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue. After installing
this update, the yum-updatesd service will be restarted automatically.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:1004-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-August/msg00001.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'yum-updatesd'
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

  if ((res = isrpmvuln(pkg:"yum-updatesd", rpm:"yum-updatesd~0.9~6.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}