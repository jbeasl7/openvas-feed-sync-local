# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63724");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
  script_cve_id("CVE-2009-1044", "CVE-2009-1169", "CVE-2009-0776", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0357", "CVE-2009-0352", "CVE-2009-0353");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-3161 (seamonkey)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"ChangeLog:

  * Fri Mar 27 2009 Christopher Aillon  - 1.15.1-3

  - Add patches for MFSA-2009-12, MFSA-2009-13

  * Wed Mar 25 2009 Christopher Aillon  - 1.15.1-2

  - Update default homepage");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update seamonkey' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3161");
  script_tag(name:"summary", value:"The remote host is missing an update to seamonkey
announced via advisory FEDORA-2009-3161.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492212");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492211");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488290");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488272");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488273");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488276");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488283");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483145");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483139");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483141");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
