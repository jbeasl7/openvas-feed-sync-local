# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63882");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
  script_cve_id("CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-0652", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2009-3875 (firefox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"ChangeLog:

  * Tue Apr 21 2009 Christopher Aillon  - 3.0.9-1

  - Update to 3.0.9

  * Fri Mar 27 2009 Christopher Aillon  - 3.0.8-1

  - Update to 3.0.8");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update firefox' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3875");
  script_tag(name:"summary", value:"The remote host is missing an update to firefox
announced via advisory FEDORA-2009-3875.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496252");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496253");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496255");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496256");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=486704");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496262");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496263");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496266");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496267");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496270");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496271");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=496274");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
