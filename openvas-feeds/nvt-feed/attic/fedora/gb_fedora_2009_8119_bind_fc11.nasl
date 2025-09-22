# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64541");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-0696");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 11 FEDORA-2009-8119 (bind)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to the latest release which fixes important security issue.
ChangeLog:

  * Wed Jul 29 2009 Adam Tkac  32:9.6.1-4.P1

  - 9.6.1-P1 release (CVE-2009-0696)

  - fix postun trigger (#513016, hopefully)

  * Mon Jul 13 2009 Adam Tkac  32:9.6.1-3

  - fix broken symlinks in bind-libs (#509635)

  - fix typos in /etc/sysconfig/named (#509650)

  - add DEBUG option to /etc/sysconfig/named (#510283)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update bind' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8119");
  script_tag(name:"summary", value:"The remote host is missing an update to bind
announced via advisory FEDORA-2009-8119.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=514292");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
