# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63387");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2008-5240", "CVE-2008-3231");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 9 FEDORA-2009-1524 (xine-lib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"This package contains the Xine library.  It can be used to play back
various media, decode multimedia files from local disk drives, and display
multimedia streamed over the Internet. It interprets many of the most
common multimedia formats available - and some uncommon formats, too.

Update Information:

This release contains one new security fix (CVE-2008-5240) and corrections of
previous security fixes.  It also includes fixes for race conditions in
gapless_switch (ref. kde bug #180339)

ChangeLog:

  * Tue Feb 10 2009 Kevin Kofler  - 1.1.16.2-1.1

  - also patch the caca version check in configure(.ac)

  * Tue Feb 10 2009 Rex Dieter  - 1.1.16.2-1

  - xine-lib-1.1.16.2

  * Mon Feb  9 2009 Rex Dieter  - 1.1.16.1-4

  - gapless-race-fix patch (kdebug#180339)

  * Sat Feb  7 2009 Rex Dieter  - 1.1.16.1-3

  - safe-audio-pause patch (kdebug#180339)

  * Mon Jan 26 2009 Rex Dieter  - 1.1.16.1-2

  - Provides: xine-lib(plugin-abi)%{?_isa} = %{abiver}

  - touchup Summary/Description

  * Fri Jan 23 2009 Rex Dieter  - 1.1.16.1-1

  - xine-lib-1.1.16.1

  - include avsync patch (#470568)

  * Sun Jan 18 2009 Rex Dieter  - 1.1.16-2

  - drop deepbind patch (#480504)

  - caca support (EPEL)

  * Wed Jan  7 2009 Kevin Kofler  - 1.1.16-1.1

  - patch for old libcaca in F9-

  * Wed Jan  7 2009 Rex Dieter  - 1.1.16-1

  - xine-lib-1.1.16, plugin ABI 1.25

  - --with-external-libdvdnav, include mpeg demuxers (#213597)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update xine-lib' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1524");
  script_tag(name:"summary", value:"The remote host is missing an update to xine-lib
announced via advisory FEDORA-2009-1524.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
