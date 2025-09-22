# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66438");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-0186", "CVE-2009-1788", "CVE-2009-1791");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-11499 (libsndfile)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Version 1.0.20 (2009-03-14)

  * Fix potential heap overflow in VOC file parser

Version 1.0.19 (2009-03-02)

  * Fix for CVE-2009-0186 (Alin Rad Pop, Secunia Research).

  * Huge number of minor bug fixes as a result of static analysis.
Version 1.0.18 (2009-02-07)

  * Add Ogg/Vorbis support (thanks to John ffitch).

  * Remove captive FLAC library.

  * Many new features and bug fixes.

ChangeLog:

  * Sat Nov 14 2009 Orcan Ogetbil  - 1.0.20-3

  - Add FLAC/Ogg/Vorbis support (BR: libvorbis-devel)

  - Make build verbose

  - Remove rpath

  - Fix ChangeLog encoding

  - Move the big Changelog to the devel package");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update libsndfile' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-11499");
  script_tag(name:"summary", value:"The remote host is missing an update to libsndfile
announced via advisory FEDORA-2009-11499.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488361");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502657");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502658");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
