# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56553");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-4077");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200603-25 (openoffice openoffice-bin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"OpenOffice.org contains a vulnerable version of libcurl that may cause a
heap overflow when parsing URLs.");
  script_tag(name:"solution", value:"All OpenOffice.org binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-bin-2.0.2'

All OpenOffice.org users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-2.0.1-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200603-25");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15756");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17951");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=126433");
  script_xref(name:"URL", value:"http://www.hardened-php.net/advisory_242005.109.html");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200512-09.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200603-25.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-office/openoffice-bin", unaffected: make_list("ge 2.0.2"), vulnerable: make_list("lt 2.0.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 2.0.1-r1"), vulnerable: make_list("lt 2.0.1-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
