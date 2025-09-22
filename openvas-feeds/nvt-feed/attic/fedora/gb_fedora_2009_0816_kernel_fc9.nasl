# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63290");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
  script_cve_id("CVE-2009-0029", "CVE-2009-0065", "CVE-2008-5079", "CVE-2008-3528", "CVE-2008-3525", "CVE-2008-3831", "CVE-2008-2750");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-0816 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

Update Information:

Update to kernel 2.6.27.12

Includes security fixes:
CVE-2009-0029 Linux Kernel insecure 64 bit system call argument passing
CVE-2009-0065 kernel: sctp: memory overflow when FWD-TSN chunk is
received with bad stream ID
Also fixes bug 478299, reported against Fedora 10:
AVC denials on kernel 2.6.27.9-159.fc10.x86_64

Reverts ALSA driver to the version that is upstream in kernel 2.6.27.
This should fix lack of audio on headphone outputs for some notebooks.

ChangeLog:

  * Mon Jan 19 2009 Chuck Ebbert  2.6.27.12-78.2.8

  - Fix CVE-2009-0065: SCTP buffer overflow

  * Mon Jan 19 2009 Chuck Ebbert  2.6.27.12-78.2.5

  - Revert ALSA to what is upstream in 2.6.27.

  * Mon Jan 19 2009 Kyle McMartin  2.6.27.12-78.2.4

  - Linux 2.6.27.12

  * Mon Jan 19 2009 Kyle McMartin

  - Roll in xen changes to execshield diff as in later kernels.
(harmless on F-9 as xen was still separate.)

  * Mon Jan 19 2009 Kyle McMartin

  - execshield fixes: should no longer generate spurious handled GPFs,
fixes randomization of executables. also some clean ups.

  * Fri Jan 16 2009 Chuck Ebbert  2.6.27.12-78.2.3.rc2

  - Linux 2.6.27.12-rc2");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0816");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-0816.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=480864");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=480861");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
