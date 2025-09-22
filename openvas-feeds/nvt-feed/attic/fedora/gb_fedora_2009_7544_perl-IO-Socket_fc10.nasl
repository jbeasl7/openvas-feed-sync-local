# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64415");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2009-3024");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fedora Core 10 FEDORA-2009-7544 (perl-IO-Socket-SSL)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

This update to version 1.26 fixes an issue where only the prefix of the hostname
was checked if there was no wildcard present, so for example www.example.org
would match a certificate starting with www.exam.

ChangeLog:

  * Sat Jul  4 2009 Paul Howarth  - 1.26-1

  - Update to 1.26 (verify_hostname_of_cert matched only the prefix for the
hostname when no wildcard was given, e.g. www.example.org matched against a
certificate with name www.exam in it)

  * Fri Jul  3 2009 Paul Howarth  - 1.25-1

  - Update to 1.25 (fix t/nonblock.t for OS X 10.5 - CPAN RT#47240)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update perl-IO-Socket-SSL' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-7544");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35587");
  script_tag(name:"summary", value:"The remote host is missing an update to perl-IO-Socket-SSL
announced via advisory FEDORA-2009-7544.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=509819");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
