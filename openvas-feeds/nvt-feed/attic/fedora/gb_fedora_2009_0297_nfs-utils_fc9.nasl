# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63212");
  script_cve_id("CVE-2009-0180");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2009-0297 (nfs-utils)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

  - Added warnings to tcp wrapper code when mounts are
  denied due to misconfigured DNS configurations.

  - gssd: By default, don't spam syslog when users'
  credentials expire
  Re-enabled and fixed/enhanced tcp wrappers.

ChangeLog:

  * Mon Jan  5 2009 Steve Dickson  1.1.2-9

  - Added warnings to tcp wrapper code when mounts are
denied due to misconfigured DNS configurations.

  - gssd: By default, don't spam syslog when users' credentials expire

  * Sat Dec 20 2008 Steve Dickson  1.1.2-8

  - Re-enabled and fixed/enhanced tcp wrappers.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update nfs-utils' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0297");
  script_tag(name:"summary", value:"The remote host is missing an update to nfs-utils
announced via advisory FEDORA-2009-0297.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=477864");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
