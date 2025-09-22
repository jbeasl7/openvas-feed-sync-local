# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64704");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2692", "CVE-2009-1897", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 23:50:03 +0000 (Thu, 08 Feb 2024)");
  script_name("Fedora Core 11 FEDORA-2009-8649 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Fix sock_sendpage null pointer dereference. CVE-2009-2692.

ChangeLog:

  * Fri Aug 14 2009 Kyle McMartin  2.6.29.6-217.2.7

  - CVE-2009-2692: Fix sock sendpage NULL ptr deref.

  * Thu Aug 13 2009 Kristian Høgsberg  - 2.6.29.6-217.2.6

  - Backport 0e7ddf7e to fix bad BUG_ON() in i915 gem fence management
code.  Adds drm-i915-gem-bad-bug-on.patch, fixes #514091.

  * Wed Aug 12 2009 John W. Linville  2.6.29.6-217.2.5

  - iwlwifi: fix TX queue race

  * Mon Aug 10 2009 Jarod Wilson  2.6.29.6-217.2.4

  - Add tunable pad threshold support to lirc_imon

  - Blacklist all iMON devices in usbhid driver so lirc_imon can bind

  - Add new device ID to lirc_mceusb (#512483)

  - Enable IR transceiver on the HD PVR

  * Wed Jul 29 2009 Chuck Ebbert  2.6.29.6-217.2.3

  - Don't optimize away NULL pointer tests where pointer is used before the test.
(CVE-2009-1897)

  * Wed Jul 29 2009 Chuck Ebbert  2.6.29.6-217.2.2

  - Fix mmap_min_addr security bugs (CVE-2009-1895)

  * Wed Jul 29 2009 Chuck Ebbert  2.6.29.6-217.2.1

  - Fix eCryptfs overflow issues (CVE-2009-2406, CVE-2009-2407)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8649");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-8649.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=516949");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
