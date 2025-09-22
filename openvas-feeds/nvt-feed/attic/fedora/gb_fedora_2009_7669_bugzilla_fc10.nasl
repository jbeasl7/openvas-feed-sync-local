# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64471");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-1213");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-7669 (bugzilla)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

New upstream version fixing Unauthorized Bug Change flaw.

ChangeLog:

  * Wed Jul  8 2009 Itamar Reis Peixoto  - 3.2.4-1

  * Mon Apr  6 2009 Itamar Reis Peixoto  3.2.3-1

  - fix CVE-2009-1213

  * Thu Mar  5 2009 Itamar Reis Peixoto  3.2.2-2

  - fix from BZ #474250 Comment #16, from Chris Eveleigh -->

  - add python BR for contrib subpackage

  - fix description

  - change Requires perl-SOAP-Lite to perl(SOAP::Lite) according guidelines");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update bugzilla' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7669");
  script_tag(name:"summary", value:"The remote host is missing an update to bugzilla
announced via advisory FEDORA-2009-7669.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
