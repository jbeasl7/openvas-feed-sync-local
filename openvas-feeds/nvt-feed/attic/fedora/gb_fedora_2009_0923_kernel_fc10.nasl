# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63287");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-02 23:28:24 +0100 (Mon, 02 Feb 2009)");
  script_cve_id("CVE-2009-0029", "CVE-2009-0065", "CVE-2008-5079");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-0923 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to kernel 2.6.27.12.

Includes security fixes:
CVE-2009-0029 Linux Kernel insecure 64 bit system call argument passing
CVE-2009-0065 kernel: sctp: memory overflow when FWD-TSN chunk is
              received with bad stream ID
              Reverts ALSA driver to the version that is upstream
              in kernel 2.6.27.

This should be the last 2.6.27 kernel update for
Fedora 10.  A 2.6.28 update kernel is being tested.

ChangeLog:

  * Tue Jan 20 2009 Chuck Ebbert

  - ath5k: ignore the return value of ath5k_hw_noise_floor_calibration
(backport to 2.6.27)

  - rtl8187: feedback transmitted packets using tx close descriptor for 8187B

  * Tue Jan 20 2009 Chuck Ebbert  2.6.27.12-170.2.4

  - Fix CVE-2009-0065: SCTP buffer overflow

  * Tue Jan 20 2009 Chuck Ebbert  2.6.27.12-170.2.3

  - Revert ALSA to what is upstream in 2.6.27.

  * Mon Jan 19 2009 Kyle McMartin

  - Linux 2.6.27.12

  - linux-2.6-iwlagn-downgrade-BUG_ON-in-interrupt.patch: merged

  - linux-2.6-iwlwifi-use-GFP_KERNEL-to-allocate-Rx-SKB-memory.patch: merged

  * Mon Jan 19 2009 Kyle McMartin

  - Roll in xen changes to execshield diff as in later kernels.

  * Mon Jan 19 2009 Kyle McMartin

  - execshield fixes: should no longer generate spurious handled GPFs,
fixes randomization of executables. also some clean ups.

  * Sun Jan 11 2009 Dave Jones

  - Don't use MAXSMP on x86-64

  * Wed Jan  7 2009 Roland McGrath  - 2.6.27.10-169

  - utrace update

  * Tue Jan  6 2009 Eric Sandeen  2.6.27.10-168

  - ext4 - delay capable() checks in space accounting (#478299)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0923");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-0923.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=478299");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=480862");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=477954");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=480866");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
