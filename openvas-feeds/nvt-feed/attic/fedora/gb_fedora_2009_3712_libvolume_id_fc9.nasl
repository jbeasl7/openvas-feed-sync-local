# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63837");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-20 23:45:17 +0200 (Mon, 20 Apr 2009)");
  script_cve_id("CVE-2009-1185", "CVE-2009-1186");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-3712 (udev)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"The udev package contains an implementation of devfs in
userspace using sysfs and netlink.

Update Information:

udev provides a user-space API and implements a dynamic device directory,
providing only the devices present on the system. udev replaces devfs in order
to provide greater hot plug functionality. Netlink is a datagram oriented
service, used to transfer information between kernel modules and user-space
processes.

It was discovered that udev did not properly check the origin of
Netlink messages. A local attacker could use this flaw to gain root privileges
via a crafted Netlink message sent to udev, causing it to create a world-
writable block device file for an existing system block device (for example, the
root file system). (CVE-2009-1185)

An integer overflow flaw, potentially
leading to heap-based buffer overflow was found in one of the utilities
providing functionality of the udev device information interface. An attacker
could use this flaw to cause a denial of service, or possibly, to execute
arbitrary code by providing a specially-crafted arguments as input to this
utility. (CVE-2009-1186)

Thanks to Sebastian Krahmer of the SUSE Security Team for responsibly
reporting this flaw.

Users of udev are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, the udevd daemon will be restarted automatically.

ChangeLog:

  * Thu Apr 16 2009 Harald Hoyer  124-4

  - fix for CVE-2009-1186

  * Tue Apr 14 2009 Harald Hoyer  124-3

  - fix for CVE-2009-1185

  * Wed Aug  6 2008 Harald Hoyer  124-2

  - added patch for cdrom tray close bug (rhbz#453095)

  - fixed udevadm syntax in start_udev (credits B.J.W. Polman)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update udev' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3712");
  script_tag(name:"summary", value:"The remote host is missing an update to udev
announced via advisory FEDORA-2009-3712.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495051");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495052");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
