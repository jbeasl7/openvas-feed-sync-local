# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64855");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
  script_cve_id("CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3073", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-9505 (epiphany-extensions)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to new upstream Firefox version 3.5.3, fixing multiple security issues.

Update also includes all packages depending on gecko-libs rebuilt
against new version of Firefox / XULRunner.

ChangeLog:

  * Wed Sep  9 2009 Jan Horak  - 2.26.1-6

  - Rebuild against newer gecko");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update epiphany-extensions' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9505");
  script_tag(name:"summary", value:"The remote host is missing an update to epiphany-extensions
announced via advisory FEDORA-2009-9505.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521684");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521686");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521687");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521688");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521689");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521690");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521691");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521693");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521694");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
