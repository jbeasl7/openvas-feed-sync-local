# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63877");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
  script_cve_id("CVE-2009-0163", "CVE-2009-0164", "CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2008-5183", "CVE-2008-5286", "CVE-2008-1722");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 15:35:00 +0000 (Thu, 28 Dec 2023)");
  script_name("Fedora Core 10 FEDORA-2009-3769 (cups)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"This update fixes several security issues: CVE-2009-0163, CVE-2009-0164,
CVE-2009-0146, CVE-2009-0147, and CVE-2009-0166.

PDF files are now converted to PostScript using the poppler package's
pdftops program.    NOTE: If your CUPS server is accessed using a
hostname or hostnames not known to the server itself you must add
ServerAlias hostname to cupsd.conf for each such name.  The special
line ServerAlias * disables checking (but this allows DNS rebinding attacks).");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update cups' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3769");
  script_tag(name:"summary", value:"The remote host is missing an update to cups
announced via advisory FEDORA-2009-3769.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490597");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490596");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490612");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490614");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490625");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
