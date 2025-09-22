# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63775");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2009-0794", "CVE-2009-0793");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 9 FEDORA-2009-3425 (java-1.6.0-openjdk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Fixes remaining LCMS issue, which resolves a TCK failure
ChangeLog:

  * Mon Apr  6 2009 Lillian Angel  - 1:1.6.0-25.b14

  - Updated java-1.6.0-openjdk-lcms.patch

  * Thu Apr  2 2009 Lillian Angel  - 1:1.6.0-0.24.b09

  - Updated java-1.6.0-openjdk-lcms.patch.

  - Resolves: rhbz#493276

  * Tue Mar 24 2009 Lillian Angel  - 1:1.6.0-0.23.b09

  - Updated java-1.6.0-openjdk-lcms.patch.

  * Tue Mar 24 2009 Lillian Angel  - 1:1.6.0-0.22.b09

  - Updated release.

  - Added java-1.6.0-openjdk-securitypatches.patch.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update java-1.6.0-openjdk' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3425");
  script_tag(name:"summary", value:"The remote host is missing an update to java-1.6.0-openjdk
announced via advisory FEDORA-2009-3425.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492367");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=492353");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
