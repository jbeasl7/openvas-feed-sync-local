# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64095");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2009-1252", "CVE-2009-0159", "CVE-2009-0021");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-5273 (ntp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update fixes a denial of service issue if autokey is enabled (default is
disabled) and a crash in ntpq.

ChangeLog:

  * Tue May 19 2009 Miroslav Lichvar  4.2.4p7-1

  - update to 4.2.4p7 (CVE-2009-1252, CVE-2009-0159)

  - don't log STA_MODE changes

  - check status in condrestart (#481261)

  - convert COPYRIGHT to UTF-8

  * Mon Jan 12 2009 Miroslav Lichvar  4.2.4p6-1

  - update to 4.2.4p6 (CVE-2009-0021)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update ntp' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-5273");
  script_tag(name:"summary", value:"The remote host is missing an update to ntp
announced via advisory FEDORA-2009-5273.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=499694");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490617");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
