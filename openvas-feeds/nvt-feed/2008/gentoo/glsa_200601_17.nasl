# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56229");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-3627", "CVE-2005-3626", "CVE-2005-3625", "CVE-2005-3624");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200601-17 (xpdf poppler gpdf libextractor pdftohtml)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Xpdf, Poppler, GPdf, libextractor and pdftohtml are vulnerable to integer
overflows that may be exploited to execute arbitrary code.");
  script_tag(name:"solution", value:"All Xpdf users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/xpdf-3.01-r5'

All Poppler users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/poppler-0.4.3-r4'

All GPdf users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/gpdf-2.10.0-r3'

All libextractor users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/libextractor-0.5.9'

All pdftohtml users should migrate to the latest stable version of
Poppler.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200601-17");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=117481");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=117494");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=117495");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=115789");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=118665");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200601-17.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-text/xpdf", unaffected: make_list("ge 3.01-r5"), vulnerable: make_list("lt 3.01-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-text/poppler", unaffected: make_list("ge 0.4.3-r4"), vulnerable: make_list("lt 0.4.3-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-text/gpdf", unaffected: make_list("ge 2.10.0-r3"), vulnerable: make_list("lt 2.10.0-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-libs/libextractor", unaffected: make_list("ge 0.5.9"), vulnerable: make_list("lt 0.5.9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-text/pdftohtml", unaffected: make_list(), vulnerable: make_list("lt 0.36-r4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
