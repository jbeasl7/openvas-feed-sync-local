# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00049.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870552");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-02-21 18:56:41 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2011-1675", "CVE-2011-1677");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2012:0307-03");
  script_name("RedHat Update for util-linux RHSA-2012:0307-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'util-linux'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"util-linux on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The util-linux package contains a large variety of low-level system
  utilities that are necessary for a Linux system to function. Among others,
  util-linux contains the fdisk configuration tool and the login program.

  Multiple flaws were found in the way the mount and umount commands
  performed mtab (mounted file systems table) file updates. A local,
  unprivileged user allowed to mount or unmount file systems could use these
  flaws to corrupt the mtab file and create a stale lock file, preventing
  other users from mounting and unmounting file systems. (CVE-2011-1675,
  CVE-2011-1677)

  This update also fixes the following bugs:

  * When the user logged into a telnet server, the login utility did not
  update the utmp database properly if the utility was executed from the
  telnetd daemon. This was due to telnetd not creating an appropriate entry
  in a utmp file before executing login. With this update, correct entries
  are created and the database is updated properly. (BZ#646300)

  * Various options were not described on the blockdev(8) manual page. With
  this update, the blockdev(8) manual page includes all the relevant options.
  (BZ#650937)

  * Prior to this update, the build process of the util-linux package failed
  in the po directory with the following error message:'@MKINSTALLDIRS@:
  No such file or directory'. An upstream patch has been applied to address
  this issue, and the util-linux package now builds successfully. (BZ#677452)

  * Previously, the ipcs(1) and ipcrm(1) manual pages mentioned an invalid
  option, '-b'. With this update, only valid options are listed on those
  manual pages. (BZ#678407)

  * Previously, the mount(8) manual page contained incomplete information
  about the ext4 and XFS file systems. With this update, the mount(8) manual
  page contains the missing information. (BZ#699639)

  In addition, this update adds the following enhancements:

  * Previously, if DOS mode was enabled on a device, the fdisk utility could
  report error messages similar to the following:

  Partition 1 has different physical/logical beginnings (non-Linux?):
  phys=(0, 1, 1) logical=(0, 2, 7)

  This update enables users to switch off DOS compatible mode (by specifying
  the '-c' option), and such error messages are no longer displayed.
  (BZ#678430)

  * This update adds the 'fsfreeze' command which halts access to a file
  system on a disk. (BZ#726572)

  All users of util-linux are advised to upgrade to this updated package,
  which contains backported patches to correct these issues and add these
  enhancements.");
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

  if ((res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.13~0.59.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"util-linux-debuginfo", rpm:"util-linux-debuginfo~2.13~0.59.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
