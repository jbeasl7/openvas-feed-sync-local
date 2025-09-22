# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64553");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-1897");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-8144 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

Update Information:

Fix security bugs:  CVE-2009-1895  CVE-2009-2406  CVE-2009-2407

ChangeLog:

  * Wed Jul 29 2009 Chuck Ebbert  2.6.29.6-217.2.3

  - Don't optimize away NULL pointer tests where pointer is used before the test.
(CVE-2009-1897)

  * Wed Jul 29 2009 Chuck Ebbert  2.6.29.6-217.2.2

  - Fix mmap_min_addr security bugs (CVE-2009-1895)

  * Wed Jul 29 2009 Chuck Ebbert  2.6.29.6-217.2.1

  - Fix eCryptfs overflow issues (CVE-2009-2406, CVE-2009-2407)

  * Thu Jul 23 2009 Kyle McMartin  2.6.29.6-217

  - Apply three patches requested by sgruszka@redhat.com:

  - iwl3945-release-resources-before-shutting-down.patch

  - iwl3945-add-debugging-for-wrong-command-queue.patch

  - iwl3945-fix-rfkill-sw-and-hw-mishmash.patch

  * Thu Jul 23 2009 Jarod Wilson

  - virtio_blk: don't bounce highmem requests, works around a frequent
oops in kvm guests using virtio block devices (#510304)

  * Wed Jul 22 2009 Tom spot Callaway

  - We have to override the new %install behavior because, well... the kernel is
special.

  * Wed Jul 22 2009 Ben Skeggs

  - drm-nouveau.patch: Fix DPMS off for DAC outputs, NV4x PFIFO typo");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8144");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-8144.
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
