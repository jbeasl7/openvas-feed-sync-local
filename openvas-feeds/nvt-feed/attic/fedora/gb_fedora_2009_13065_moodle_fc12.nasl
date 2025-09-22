# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66502");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2009-4297", "CVE-2009-4298", "CVE-2009-4299", "CVE-2009-4300",
                "CVE-2009-4301", "CVE-2009-4302", "CVE-2009-4303", "CVE-2009-4304",
                "CVE-2009-4305");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 12 FEDORA-2009-13065 (moodle)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Moodle upstream has released latest stable versions (1.9.7 and 1.8.11), fixing
multiple security issues.    For details, please visit the referenced
security advisroies.

ChangeLog:

  * Tue Dec  8 2009 Jon Ciesla  - 1.9.7-1

  - Update to 1.9.7, BZ 544766.

  * Thu Nov  5 2009 Jon Ciesla  - 1.9.6-2

  - Reverted erroneous cron fix.

  * Thu Nov  5 2009 Jon Ciesla  - 1.9.6-1

  - Update to 1.9.6.

  - Make moodle-cron honor lock, BZ 533171.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update moodle' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13065");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37244");
  script_tag(name:"summary", value:"The remote host is missing an update to moodle
announced via advisory FEDORA-2009-13065.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=544766");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
