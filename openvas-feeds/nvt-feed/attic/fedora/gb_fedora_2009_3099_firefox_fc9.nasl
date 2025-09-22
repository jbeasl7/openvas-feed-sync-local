# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63721");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
  script_cve_id("CVE-2009-1169", "CVE-2009-1044");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-3099 (firefox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox.    A memory corruption flaw was
discovered in the way Firefox handles XML files containing an XSLT transform. A
remote attacker could use this flaw to crash Firefox or, potentially, execute
arbitrary code as the user running Firefox. (CVE-2009-1169)    A flaw was
discovered in the way Firefox handles certain XUL garbage collection events. A
remote attacker could use this flaw to crash Firefox or, potentially, execute
arbitrary code as the user running Firefox. (CVE-2009-1044)

This update also provides depending packages rebuilt against new Firefox
version.    Miro updates to upstream 2.0.3.  Provides new features and
fixes various bugs in 1.2.x series

ChangeLog:

  * Fri Mar 27 2009 Christopher Aillon  - 3.0.8-1

  - Update to 3.0.8

  * Wed Mar  4 2009 Jan Horak  - 3.0.7-1

  - Update to 3.0.7");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update firefox' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3099");
  script_tag(name:"summary", value:"The remote host is missing an update to firefox
announced via advisory FEDORA-2009-3099.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
