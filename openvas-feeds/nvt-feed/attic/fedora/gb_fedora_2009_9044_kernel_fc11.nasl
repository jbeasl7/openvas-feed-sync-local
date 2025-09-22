# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64736");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-2691", "CVE-2009-2848", "CVE-2009-2849", "CVE-2009-2847", "CVE-2009-2695", "CVE-2009-2767", "CVE-2009-2692", "CVE-2009-1897", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 23:50:03 +0000 (Thu, 08 Feb 2024)");
  script_name("Fedora Core 11 FEDORA-2009-9044 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Security fixes:

  - CVE-2009-2691: Information disclosure in proc filesystem

  - CVE-2009-2848: execve: must clear current->child_tid

  - CVE-2009-2849: md: null pointer dereference

  - CVE-2009-2847: Information leak in do_sigaltstack

Restore missing LIRC drivers, dropped in previous release.
Backport upstream fixes that further improve the security of
mmap of low addresses.  (CVE-2009-2695)

ChangeLog:

  * Thu Sep 24(??!!) 2009 Chuck Ebbert  2.6.29.6-217.2.16

  - Fix CVE-2009-2691: local information disclosure in /proc

  * Fri Aug 21 2009 David Woodhouse

  - Fix b43 on iMac G5 (#514787)

  * Tue Aug 18 2009 Kyle McMartin

  - CVE-2009-2848: execve: must clear current->clear_child_tid

  - Cherry pick upstream commits 52dec22e739eec8f3a0154f768a599f5489048bd
which improve mmap_min_addr.

  - CVE-2009-2849: md: avoid dereferencing null ptr when accessing suspend
sysfs attributes.

  - CVE-2009-2847: do_sigaltstack: avoid copying 'stack_t' as a structure
to userspace");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9044");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-9044.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=516171");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=515423");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=518132");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=515392");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=517830");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
