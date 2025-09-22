# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63667");
  script_version("2025-01-13T08:32:03+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-1148", "CVE-2009-1149", "CVE-2009-1150", "CVE-2009-1151");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:48:50 +0000 (Tue, 16 Jul 2024)");
  script_name("Fedora Core 9 FEDORA-2009-2984 (phpMyAdmin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Improvements for 3.1.3.1:

  - [security] HTTP Response Splitting and file inclusion vulnerabilities

  - [security] XSS vulnerability on export page

  - [security] Insufficient output sanitizing when generating configuration file

ChangeLog:

  * Wed Mar 25 2009 Robert Scheck  3.1.3.1-1

  - Upstream released 3.1.3.1 (#492066)

  * Sun Mar  1 2009 Robert Scheck  3.1.3-1

  - Upstream released 3.1.3");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update phpMyAdmin' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2984");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34236");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34253");
  script_tag(name:"summary", value:"The remote host is missing an update to phpMyAdmin
announced via advisory FEDORA-2009-2984.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492066");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
