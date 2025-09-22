# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63385");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2008-4298", "CVE-2008-4359", "CVE-2008-4360");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2008-11923 (lighttpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"This update fixes some moderate security issues and includes a few enhancements.

ChangeLog:

  * Wed Dec 24 2008 Matthias Saou  1.4.20-6

  - Partially revert last change by creating a spawn-fastcgi symlink, so that
nothing breaks currently (especially for EL).

  - Install empty poweredby image on RHEL since the symlink's target is missing.

  - Split spawn-fcgi off in its own sub-package, have fastcgi package require it
to provide backwards compatibility.

  * Mon Dec 22 2008 Matthias Saou  1.4.20-3

  - Rename spawn-fastcgi to lighttpd-spawn-fastcgi to avoid clash with other
packages providing it for their own needs (#472749). It's not used as-is
by lighttpd, so it shouldn't be a problem... at worst, some custom scripts
will need to be updated.

  * Mon Dec 22 2008 Matthias Saou  1.4.20-2

  - Include conf.d/*.conf configuration snippets (#444953).

  - Mark the default index.html in order to not loose changes upon upgrade if it
was edited or replaced with a different file (#438564).

  - Include patch to add the INIT INFO block to the init script (#246973).");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update lighttpd' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2008-11923");
  script_tag(name:"summary", value:"The remote host is missing an update to lighttpd
announced via advisory FEDORA-2008-11923.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=464637");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=465751");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=465752");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
