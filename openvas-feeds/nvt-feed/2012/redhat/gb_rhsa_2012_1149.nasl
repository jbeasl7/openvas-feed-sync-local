# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-August/msg00006.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870807");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-08-09 10:21:05 +0530 (Thu, 09 Aug 2012)");
  script_cve_id("CVE-2012-3440");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:C/A:C");
  script_xref(name:"RHSA", value:"2012:1149-01");
  script_name("RedHat Update for sudo RHSA-2012:1149-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"sudo on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The sudo (superuser do) utility allows system administrators to give
  certain users the ability to run commands as root.

  An insecure temporary file use flaw was found in the sudo package's
  post-uninstall script. A local attacker could possibly use this flaw to
  overwrite an arbitrary file via a symbolic link attack, or modify the
  contents of the '/etc/nsswitch.conf' file during the upgrade or removal of
  the sudo package. (CVE-2012-3440)

  This update also fixes the following bugs:

  * Previously, sudo escaped non-alphanumeric characters in commands using
  'sudo -s' or 'sudo -' at the wrong place and interfered with the
  authorization process. Some valid commands were not permitted. Now,
  non-alphanumeric characters escape immediately before the command is
  executed and no longer interfere with the authorization process.
  (BZ#844418)

  All users of sudo are advised to upgrade to this updated package, which
  contains backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.2p1~14.el5_8.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.7.2p1~14.el5_8.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
