# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64546");
  script_cve_id("CVE-2009-3156");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_name("Fedora Core 10 FEDORA-2009-8162 (drupal-date)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"The Date API is available to be used by other modules and is not dependent
on having CCK installed.  The date module is a flexible date/time field
type for the cck content module which requires the CCK content.module and
the Date API module.

Update Information:

  * Advisory ID: DRUPAL-SA-CONTRIB-2009-046

  * Project: Date (third-party module)

  * Version: 6.x

  * Date: 2009-July-29

  * Security risk: Moderately critical

  * Exploitable from: Remote

  * Vulnerability: Cross Site Scripting

The Date module provides a date CCK field that can be added to any content
type. The Date Tools module that is bundled with Date module does not  properly
escape user input when displaying labels for fields on a content  type. A
malicious user with the 'use date tools' permission of the Date Tools  sub-
module, or the 'administer content types' permission could attempt a  cross site
scripting (XSS) attack when creating a new content type, leading to the
user gaining full administrative access.

  - ------- VERSIONS AFFECTED
prior to 6.x-2.3    Drupal core is not affected. If you do not use the
contributed Date module, there is nothing you need to do.

ChangeLog:

  * Wed Jul 29 2009 Jon Ciesla  - 6.x.2.3-0

  - Update to new version.

  - Fix for DRUPAL-SA-CONTRIB-2009-046.

  * Fri Jul 24 2009 Fedora Release Engineering  - 6.x.2.0-2.rc4.2");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update drupal-date' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8162");
  script_tag(name:"summary", value:"The remote host is missing an update to drupal-date
announced via advisory FEDORA-2009-8162.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
