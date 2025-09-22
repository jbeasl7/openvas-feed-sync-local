# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64629");
  script_cve_id("CVE-2009-3618", "CVE-2009-3619");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 11 FEDORA-2009-8507 (viewvc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

CHANGES in 1.1.2:

  - security fix: validate the 'view' parameter to avoid XSS attack

  - security fix: avoid printing illegal parameter names and values

  - add optional support for character encoding detection (issue #400)

  - fix username case handling in svnauthz module (issue #419)

  - fix cvsdbadmin/svnadmin rebuild error on missing repos (issue #420)

  - don't drop leading blank lines from colorized file contents (issue #422)

  - add file.ezt template logic for optionally hiding binary file contents

Also includes:    Install and populate mimetypes.conf. This should
hopefully help when colouring syntax using pygments.
Install and populate mimetypes.conf.

ChangeLog:

  * Wed Aug 12 2009 Bojan Smojver  - 1.1.2-2

  - fix replacement of various config variables

  * Wed Aug 12 2009 Bojan Smojver  - 1.1.2-1

  - bump up to 1.1.2

  - security fix: validate the 'view' parameter to avoid XSS attack

  - security fix: avoid printing illegal parameter names and values

  * Tue Aug 11 2009 Bojan Smojver  - 1.1.1-2

  - install mimetypes.conf

  - populate mimetypes.conf with what pygments understands");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update viewvc' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8507");
  script_tag(name:"summary", value:"The remote host is missing an update to viewvc
announced via advisory FEDORA-2009-8507.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=516958");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=514909");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=514773");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
