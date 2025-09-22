# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64814");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
  script_cve_id("CVE-2009-0200", "CVE-2009-0201");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-9256 (openoffice.org)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

CVE-2009-0200/CVE-2009-0201: Harden .doctable insert/delete record import
handling.

ChangeLog:

  * Wed Sep  2 2009 Caolán McNamara  - 1:3.0.1-15.6

  - Resolves: rhbz#520772 copy/paste cockup

  * Mon Aug 31 2009 Caolán McNamara  - 1:3.0.1-15.5

  - Resolves: CVE-2009-0200/CVE-2009-0201

  - Resolves: rhbz#499474 soffice and .recently-used.xbel

  - Resolves: rhbz#504419  openoffice.org-3.1.0.ooo102566.sc.less.frenetic.progress.patch

  - Resolves: rhbz#506039 workspace.pdfextfix02.patch upsidedown images in pdf import

  - Resolves: rhbz#514683 add openoffice.org-3.1.1.ooo104329.dbaccess.primarykeys.patch

  - make the last three patches applicable

  - Resolves: rbhz#501141 Images and Frames disappear in sequential printing");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update openoffice.org' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9256");
  script_tag(name:"summary", value:"The remote host is missing an update to openoffice.org
announced via advisory FEDORA-2009-9256.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=500993");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=502194");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
