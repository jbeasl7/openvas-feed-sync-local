# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63673");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-3034 (java-1.6.0-openjdk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

lcms in OpenJDK upgraded to 1.18 fixing many related security issues.
ChangeLog:

  * Tue Mar 24 2009 Lillian Angel  - 1:1.6.0-0.23.b09

  - Updated java-1.6.0-openjdk-lcms.patch.

  * Tue Mar 24 2009 Lillian Angel  - 1:1.6.0-0.22.b09

  - Updated release.

  - Added java-1.6.0-openjdk-securitypatches.patch.

  * Fri Mar 20 2009 Lillian Angel  - 1:1.6.0-0.21.b09

  - Added new lcms security patch.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update java-1.6.0-openjdk' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3034");
  script_tag(name:"summary", value:"The remote host is missing an update to java-1.6.0-openjdk
announced via advisory FEDORA-2009-3034.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=487509");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=487508");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=487512");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
