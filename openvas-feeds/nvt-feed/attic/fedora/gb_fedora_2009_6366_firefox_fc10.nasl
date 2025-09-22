# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64230");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:03:54 +0000 (Fri, 02 Feb 2024)");
  script_name("Fedora Core 10 FEDORA-2009-6366 (firefox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to new upstream Firefox version 3.0.11, fixing multiple security issues.

Update also includes all packages depending on gecko-libs rebuild
against new version of Firefox / XULRunner.

ChangeLog:

  * Thu Jun 11 2009 Christopher Aillon  - 3.0.11-1

  - Update to 3.0.11

  * Mon Apr 27 2009 Jan Horak  - 3.0.10-1

  - Update to 3.0.10

  * Tue Apr 21 2009 Christopher Aillon  - 3.0.9-1

  - Update to 3.0.9

  * Fri Mar 27 2009 Christopher Aillon  - 3.0.8-1

  - Update to 3.0.8

  * Wed Mar  4 2009 Jan Horak  - 3.0.7-1

  - Update to 3.0.7

  * Thu Feb 26 2009 Jan Horak  - 3.0.6-2

  - Fixed spelling mistake in firefox.sh.in

  * Wed Feb  4 2009 Christopher Aillon  - 3.0.6-1

  - Update to 3.0.6

  * Wed Jan  7 2009 Jan Horak  - 3.0.5-2

  - Fixed wrong LANG and LC_MESSAGES variables interpretation (#441973)
in startup script.

  * Tue Dec 16 2008 Christopher Aillon  3.0.5-1

  - Update to 3.0.5

  * Thu Nov 13 2008 Jan Horak  3.0.4-2

  - Removed firefox-2.0-getstartpage.patch patch

  - Start page is set by different way");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update firefox' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6366");
  script_tag(name:"summary", value:"The remote host is missing an update to firefox
announced via advisory FEDORA-2009-6366.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503568");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503569");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503570");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503573");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503576");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503578");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503579");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503580");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503581");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503582");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=503583");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
