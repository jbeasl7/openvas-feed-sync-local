# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-August/018791.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881468");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-09 10:21:39 +0530 (Thu, 09 Aug 2012)");
  script_cve_id("CVE-2012-3440");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:C/A:C");
  script_xref(name:"CESA", value:"2012:1149");
  script_name("CentOS Update for sudo CESA-2012:1149 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"sudo on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

  * Prior to this update, the sudo utility could, under certain
  circumstances, fail to receive the SIGCHLD signal when it was executed
  from a process that blocked the SIGCHLD signal. As a consequence, sudo
  could become suspended and fail to exit. This update modifies the signal
  process mask so that sudo can exit and sends the correct output.
  (BZ#844419)

  * The sudo update RHSA-2012:0309 introduced a regression that caused the
  Security-Enhanced Linux (SELinux) context of the '/etc/nsswitch.conf' file
  to change during the installation or upgrade of the sudo package. This
  could cause various services confined by SELinux to no longer be permitted
  to access the file. In reported cases, this issue prevented PostgreSQL and
  Postfix from starting. (BZ#842759)

  * Updating the sudo package resulted in the 'sudoers' line in
  '/etc/nsswitch.conf' being removed. This update corrects the bug in the
  sudo package's post-uninstall script that caused this issue. (BZ#844420)

  * Prior to this update, a race condition bug existed in sudo. When a
  program was executed with sudo, the program could possibly exit
  successfully before sudo started waiting for it. In this situation, the
  program would be left in a zombie state and sudo would wait for it
  endlessly, expecting it to still be running. (BZ#844978)

  All users of sudo are advised to upgrade to this updated package, which
  contains backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.2p1~14.el5_8.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
