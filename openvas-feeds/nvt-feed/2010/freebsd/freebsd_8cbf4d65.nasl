# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68000");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2756", "CVE-2010-2757", "CVE-2010-2758", "CVE-2010-2759");
  script_name("FreeBSD Ports: bugzilla");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: bugzilla

CVE-2010-2756
Search.pm in Bugzilla 2.19.1 through 3.2.7, 3.3.1 through 3.4.7, 3.5.1
through 3.6.1, and 3.7 through 3.7.2 allows remote attackers to
determine the group memberships of arbitrary users via vectors
involving the Search interface, boolean charts, and group-based
pronouns.

CVE-2010-2757
The sudo feature in Bugzilla 2.22rc1 through 3.2.7, 3.3.1 through
3.4.7, 3.5.1 through 3.6.1, and 3.7 through 3.7.2 does not properly
send impersonation notifications, which makes it easier for remote
authenticated users to impersonate other users without discovery.

CVE-2010-2758
Bugzilla 2.17.1 through 3.2.7, 3.3.1 through 3.4.7, 3.5.1 through
3.6.1, and 3.7 through 3.7.2 generates different error messages
depending on whether a product exists, which makes it easier for
remote attackers to guess product names via unspecified use of the (1)
Reports or (2) Duplicates page.

CVE-2010-2759
Bugzilla 2.23.1 through 3.2.7, 3.3.1 through 3.4.7, 3.5.1 through
3.6.1, and 3.7 through 3.7.2, when PostgreSQL is used, does not
properly handle large integers in (1) bug and (2) attachment phrases,
which allows remote authenticated users to cause a denial of service
(bug invisibility) via a crafted comment.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=417048");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=450013");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=577139");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=519835");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=583690");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/8cbf4d65-af9a-11df-89b8-00151735203a.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"bugzilla");
if(!isnull(bver) && revcomp(a:bver, b:"2.17.1")>0 && revcomp(a:bver, b:"3.6.2")<0) {
  txt += 'Package bugzilla version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}