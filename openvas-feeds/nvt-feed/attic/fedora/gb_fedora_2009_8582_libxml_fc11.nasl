# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64701");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2004-0110", "CVE-2004-0989", "CVE-2009-2414", "CVE-2009-2416");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:04:10 +0000 (Fri, 02 Feb 2024)");
  script_name("Fedora Core 11 FEDORA-2009-8582 (libxml)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"This library allows old Gnome-1 applications to manipulate XML files.

Update Information:

This update includes patches from RHEL-3 addressing a number of security
vulnerabilities:

  - CVE-2004-0110 (arbitrary code execution via a long URL)

  - CVE-2004-0989 (arbitrary code execution via a long URL)

  - CVE-2009-2414 (stack consumption DoS vulnerabilities)

  - CVE-2009-2416 (use-after-free DoS vulnerabilities)

ChangeLog:

  * Wed Aug 12 2009 Paul Howarth  1:1.8.17-24

  - renumber existing patches to free up low-numbered patches for EL-3 patches

  - add patch for CAN-2004-0110 and CAN-2004-0989 (#139090)

  - add patch for CVE-2009-2414 and CVE-2009-2416 (#515195, #515205)

  * Sat Jul 25 2009 Fedora Release Engineering  1:1.8.17-23


  * Mon Apr 20 2009 Paul Howarth  1:1.8.17-22

  - rebuild for %{_isa} provides/requires");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update libxml' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8582");
  script_tag(name:"summary", value:"The remote host is missing an update to libxml
announced via advisory FEDORA-2009-8582.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=430644");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=430645");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=515195");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=515205");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
