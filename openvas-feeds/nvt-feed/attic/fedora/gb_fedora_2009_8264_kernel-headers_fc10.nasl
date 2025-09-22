# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64551");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-1897", "CVE-2009-0065", "CVE-2008-5079");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-8264 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to linux kernel 2.6.27.29

Fixes security bugs:  CVE-2009-1895  CVE-2009-2406  CVE-2009-2407

ChangeLog:

  * Fri Jul 31 2009 Chuck Ebbert   2.6.27.29-170.2.78

  - The kernel package needs to override the new rpm %install behavior.

  * Thu Jul 30 2009 Chuck Ebbert   2.6.27.29-170.2.77

  - Linux 2.6.27.29

  * Wed Jul 29 2009 Chuck Ebbert   2.6.27.29-170.2.75.rc1

  - Linux 2.6.27.29-rc1 (CVE-2009-2406, CVE-2009-2407)

  - Drop linux-2.6-netdev-r8169-avoid-losing-msi-interrupts.patch, now in -stable.

  * Wed Jul 29 2009 Chuck Ebbert   2.6.27.28-170.2.74

  - Don't bounce virtio_blk requests (#510304)

  * Mon Jul 27 2009 Chuck Ebbert   2.6.27.28-170.2.73

  - Linux 2.6.27.28 (CVE-2009-1895, CVE-2009-1897)
Dropped patches, merged in stable:
linux-2.6-kbuild-fix-unifdef.c-usage-of-getline.patch
linux-2.6-netdev-r8169-fix-lg-pkt-crash.patch
New config item:
CONFIG_DEFAULT_MMAP_MIN_ADDR=32768");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8264");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-8264.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=511171");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512861");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512885");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
