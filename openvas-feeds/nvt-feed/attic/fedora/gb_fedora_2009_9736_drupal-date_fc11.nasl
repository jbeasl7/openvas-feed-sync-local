# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_xref(name:"URL", value:"http://en.wikipedia.org/wiki/Cross-site_scripting");
  script_xref(name:"URL", value:"http://drupal.org/node/579000");
  script_xref(name:"URL", value:"http://drupal.org/node/578998");
  script_xref(name:"URL", value:"http://drupal.org/project/date");
  script_xref(name:"URL", value:"http://drupal.org/user/45874");
  script_oid("1.3.6.1.4.1.25623.1.0.64915");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-21 23:13:00 +0200 (Mon, 21 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 11 FEDORA-2009-9736 (drupal-date)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

  * Advisory ID: DRUPAL-SA-CONTRIB-2009-057

  * Project: Date (third-party module)

  * Version: 5.x, 6.x

  * Date: 2009-September-16

  * Security risk: Moderately critical

  * Exploitable from: Remote

  * Vulnerability: Cross Site Scripting


ChangeLog:

  * Wed Sep 16 2009 Jon Ciesla  - 6.x.2.4-0

  - Update to new version.

  - Fix for DRUPAL-SA-CONTRIB-2009-057.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update drupal-date' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9736");
  script_tag(name:"summary", value:"The remote host is missing an update to drupal-date
announced via advisory FEDORA-2009-9736.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
