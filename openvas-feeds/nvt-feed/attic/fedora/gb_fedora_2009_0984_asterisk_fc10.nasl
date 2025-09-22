# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63389");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2009-0041");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 10 FEDORA-2009-0984 (asterisk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Add a patch to fix a problem with the manager interface.
Update to 1.6.0.5 to fix AST-2009-001 / CVE-2009-0041.

(Original patch in 1.6.0.3 introduced a regression.)

ChangeLog:

  * Fri Jan 23 2009 Jeffrey C. Ollie  - 1.6.0.5-2

  - Add a patch to fix a problem with the manager interface.

  * Fri Jan 23 2009 Jeffrey C. Ollie  - 1.6.0.5-1

  - Update to 1.6.0.5 to fix regressions caused by fixes for
AST-2009-001/CVE-2009-0041 (Asterisk 1.6.0.4 was never released).

  * Thu Jan  8 2009 Jeffrey C. Ollie  - 1.6.0.3-1

  - Update to 1.6.0.3 to fix AST-2009-001/CVE-2009-0041

  * Sun Jan  4 2009 Jeffrey C. Ollie  - 1.6.0.2-4

  - Fedora Directory Server compatibility patch/subpackage. BZ#452176

  * Sun Jan  4 2009 Jeffrey C. Ollie  - 1.6.0.2-3

  - Don't package func_curl in the main package. BZ#475910

  - Fix up paths. BZ#477238

  * Sun Jan  4 2009 Jeffrey C. Ollie  - 1.6.0.2-2

  - Add patch to fix compilation on PPC

  * Sun Jan  4 2009 Jeffrey C. Ollie  - 1.6.0.2-1

  - Update to 1.6.0.2

  * Wed Nov  5 2008 Jeffrey C. Ollie  - 1.6.0.1-3

  - Fix issue with init script giving wrong path to config file.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update asterisk' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0984");
  script_tag(name:"summary", value:"The remote host is missing an update to asterisk
announced via advisory FEDORA-2009-0984.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=480132");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
