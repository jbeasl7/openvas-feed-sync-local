# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64296");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2008-3528", "CVE-2008-3525", "CVE-2008-3831", "CVE-2008-2750", "CVE-2009-1385", "CVE-2009-1389");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Fedora Core 9 FEDORA-2009-6846 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to linux kernel 2.6.27.25

ChangeLog:

  * Tue Jun 16 2009 Chuck Ebbert  2.6.27.25-78.2.56

  - r8169 network driver fixes from 2.6.29.5 and 2.6.30

  * Tue Jun 16 2009 Chuck Ebbert  2.6.27.25-78.2.55

  - Avoid lockup on OOM with /dev/zero

  - Stop spewing useless warning on parport sysctl registration

  * Sun Jun 14 2009 Chuck Ebbert   2.6.27.25-78.2.54

  - Linux 2.6.27.25

  - Dropped patches, merged in .25
ext4.git-1-8657e625a390d09a21970a810f271d74e99b4c8f.patch
ext4.git-2-b3239aab20df1446ddfb8d0520076d5fd0d4ecd2.patch
ext4.git-3-e9b9a50398f0cc909e5645716c74cc1aecd6699e.patch
ext4.git-4-ce54e9c7949d1158512accf23825641a92bd07f9.patch
ext4.git-5-e0ee7aa0b15299bc678758a754eec51ee537c53f.patch
linux-2.6-ext4-clear-unwritten-flag.patch
linux-2.6-ext4-fake-delalloc-bno.patch
linux-2.6-ext4-fix-i_cached_extent-race.patch
linux-2.6-ext4-prealloc-fixes.patch

  - Added patch from 2.6.29.4:
kvm-make-efer-reads-safe-when-efer-does-not-exist.patch");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6846");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-6846.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502981");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=504726");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
