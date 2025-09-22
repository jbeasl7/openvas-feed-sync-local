# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64410");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-2265", "CVE-2008-3381", "CVE-2008-0781", "CVE-2009-0260", "CVE-2009-0312");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-7761 (moin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update removes the filemanager and _samples directories from the embedded
FCKeditor, they contain code with known security vulnerabilities, even though
that code couldn't be invoked when Moin was used with the default settings. Moin
was probably not affected, but installing this update is still recommended as a
security measure. CVE-2009-2265 is the related CVE identifier.

ChangeLog:

  * Sun Jul 12 2009 Ville-Pekka Vainio  1.6.4-3

  - Remove the filemanager and _samples directories from the embedded FCKeditor,
they contain code with know security vulnerabilities, even though that code
probably couldn't be invoked when moin was used with the default settings.

  - Fixes rhbz #509924, related to CVE-2009-2265

  * Sat Jun 13 2009 Ville-Pekka Vainio  1.6.4-2

  - Hierarchical ACL security fix from 1.8.4, 1.8 HG 897cdbe9e8f2

  - Convert CHANGES to UTF-8");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update moin' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7761");
  script_tag(name:"summary", value:"The remote host is missing an update to moin
announced via advisory FEDORA-2009-7761.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=509924");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
