# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54824");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0452", "CVE-2005-0077", "CVE-2005-0448");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200501-38 (Perl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"The Perl DBI library and File::Path::rmtree function are vulnerable to
symlink attacks.");
  script_tag(name:"solution", value:"All Perl users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/perl

All DBI library users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-perl/DBI");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200501-38");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=75696");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=78634");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=79685");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200501-38.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-perl/DBI", unaffected: make_list("rge 1.37-r1", "ge 1.38-r1"), vulnerable: make_list("le 1.38"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-lang/perl", unaffected: make_list("ge 5.8.6-r4", "rge 5.8.5-r5", "rge 5.8.4-r4", "rge 5.8.2-r4"), vulnerable: make_list("le 5.8.6-r3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
