# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66094");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
  script_cve_id("CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609", "CVE-2009-3605", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-10694 (xpdf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

  - apply xpdf-3.02pl4 security patch to fix:    CVE-2009-1188/CVE-2009-3603,
CVE-2009-3604, CVE-2009-3606, CVE-2009-3608, CVE-2009-3609

ChangeLog:

  * Fri Oct 16 2009 Tom spot Callaway  - 1:3.02-15

  - apply xpdf-3.02pl4 security patch to fix:
CVE-2009-3603, CVE-2009-3604, CVE-2009-3605, CVE-2009-3606
CVE-2009-3608, CVE-2009-3609");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update xpdf' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10694");
  script_tag(name:"summary", value:"The remote host is missing an update to xpdf
announced via advisory FEDORA-2009-10694.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495907");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526911");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526877");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526637");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526893");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
