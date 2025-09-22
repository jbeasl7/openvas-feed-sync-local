# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64074");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2009-0065", "CVE-2008-5079", "CVE-2009-1242", "CVE-2009-1337", "CVE-2009-1439", "CVE-2009-1633");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-5356 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Includes ext4 bug fixes from Fedora 11.
Updates the atl2 network driver to version 2.0.5

ChangeLog:

  * Wed May 20 2009 Chuck Ebbert   2.6.27.24-170.2.68

  - Enable Divas (formerly Eicon) ISDN drivers on x86_64. (#480837)

  * Wed May 20 2009 Chuck Ebbert   2.6.27.24-170.2.67

  - Enable sfc driver for Solarflare SFC4000 network adapter (#499392)
(disabled on powerpc)

  * Wed May 20 2009 Chuck Ebbert   2.6.27.24-170.2.66

  - Add workaround for Intel Atom erratum AAH41 (#499803)

  * Wed May 20 2009 Chuck Ebbert   2.6.27.24-170.2.65

  - Allow building the F-10 2.6.27 kernel on F-11.

  * Wed May 20 2009 Chuck Ebbert   2.6.27.24-170.2.64

  - ext4 fixes from Fedora 11:
linux-2.6-ext4-clear-unwritten-flag.patch
linux-2.6-ext4-fake-delalloc-bno.patch
linux-2.6-ext4-fix-i_cached_extent-race.patch
linux-2.6-ext4-prealloc-fixes.patch

  * Wed May 20 2009 Chuck Ebbert   2.6.27.24-170.2.63

  - Merge official ext4 patches headed for -stable.

  - Drop ext4 patches we already had:
linux-2.6.27-ext4-fix-header-check.patch
linux-2.6.27-ext4-print-warning-once.patch
linux-2.6.27-ext4-fix-bogus-bug-ons-in-mballoc.patch
linux-2.6.27-ext4-fix-bb-prealloc-list-corruption.patch

  * Wed May 20 2009 Chuck Ebbert   2.6.27.24-170.2.62

  - Add patches from Fedora 9:
Update the atl2 network driver to version 2.0.5
KVM: don't allow access to the EFER from 32-bit x86 guests

  * Wed May 20 2009 Chuck Ebbert   2.6.27.24-170.2.61

  - Linux 2.6.27.24

  - Fix up execshield, utrace, r8169 and drm patches for .24");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-5356");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-5356.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502109");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=493771");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=494275");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496572");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
