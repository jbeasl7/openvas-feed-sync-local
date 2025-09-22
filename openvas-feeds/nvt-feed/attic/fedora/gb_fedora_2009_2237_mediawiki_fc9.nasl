# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63487");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-03-07 21:47:03 +0100 (Sat, 07 Mar 2009)");
  script_cve_id("CVE-2008-5249", "CVE-2008-5250", "CVE-2008-5252", "CVE-2008-5687", "CVE-2008-5688", "CVE-2009-0737");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2009-2237 (mediawiki)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"This update fixes the XSS vulnerabilities in 1.13.3 and splits the package into
a non-math and a full package to allow for smaller installs where embedded math
is not required.

ChangeLog:

  * Sat Feb 28 2009 Axel Thimm  - 1.14.0-45

  - Update to 1.14.0.

  * Sun Feb 22 2009 Axel Thimm  - 1.13.4-44

  - Split package up, so some users can decide to not install math
support (results in smaller installs), see RH bug #485447.

  * Wed Feb 18 2009 Axel Thimm  - 1.13.4-43

  - Update to 1.13.4, closes RH bug #485728.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update mediawiki' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2237");
  script_tag(name:"summary", value:"The remote host is missing an update to mediawiki
announced via advisory FEDORA-2009-2237.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=487489");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
