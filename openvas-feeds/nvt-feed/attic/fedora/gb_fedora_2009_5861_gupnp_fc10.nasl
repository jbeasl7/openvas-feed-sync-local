# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64231");
  script_cve_id("CVE-2009-2174");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-5861 (gupnp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

New upstream release that fixes a bug where the gupnp stack crashes when passed
empty content.

Other bugs fixed:

  - bug#1570: gupnp doesn't set the pkgconfig lib dir correctly in 64 bit env.

  - bug#1574: Avoid using asserts.

  - bug#1592: gupnp_device_info_get_icon_url() does not return the closest match.

  - bug#1604: Crash on action without any content.

ChangeLog:

  * Wed Jun  3 2009 Peter Robinson  0.12.8-1

  - New upstream release

  * Mon Apr 27 2009 Peter Robinson  0.12.7-1

  - New upstream release

  * Wed Mar  4 2009 Peter Robinson  0.12.6-4

  - Move docs to noarch sub package

  * Mon Mar  2 2009 Peter Robinson  0.12.6-3

  - Add some extra -devel Requires packages

  * Tue Feb 24 2009 Fedora Release Engineering  - 0.12.6-2

  * Mon Feb 23 2009 Peter Robinson  0.12.6-1

  - New upstream release

  * Wed Jan 14 2009 Peter Robinson  0.12.5-1

  - New upstream release

  * Thu Dec 18 2008 Peter Robinson  0.12.4-3

  - Add gtk-doc build req

  * Sat Nov 22 2008 Peter Robinson  0.12.4-2

  - Fix summary

  * Mon Nov 17 2008 Peter Robinson  0.12.4-1

  - New upstream release");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update gupnp' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-5861");
  script_tag(name:"summary", value:"The remote host is missing an update to gupnp
announced via advisory FEDORA-2009-5861.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
