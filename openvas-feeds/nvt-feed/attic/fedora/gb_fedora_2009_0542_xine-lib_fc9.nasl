# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63213");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_cve_id("CVE-2008-5234", "CVE-2008-5236", "CVE-2008-5237", "CVE-2008-5239", "CVE-2008-5240", "CVE-2008-5243", "CVE-2008-3231");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-0542 (xine-lib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This updates xine-lib to the upstream 1.1.16 release.
This fixes several bugs, including the security issues
CVE-2008-5234 vector 1, CVE-2008-5236, CVE-2008-5237,
CVE-2008-5239, CVE-2008-5240 vectors 3 & 4 and CVE-2008-5243.

In addition, the Fedora xine-lib package now
includes the demuxers for the MPEG container format,
which are not patent-encumbered. (The decoders for actual
MPEG video and audio data are still excluded due to
software patents.)

ChangeLog:

  * Wed Jan  7 2009 Kevin Kofler  - 1.1.16-1.1

  - patch for old libcaca in F9-

  * Wed Jan  7 2009 Rex Dieter  - 1.1.16-1

  - xine-lib-1.1.16, plugin ABI 1.25

  - --with-external-libdvdnav, include mpeg demuxers (#213597)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update xine-lib' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0542");
  script_tag(name:"summary", value:"The remote host is missing an update to xine-lib
announced via advisory FEDORA-2009-0542.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=213597");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
