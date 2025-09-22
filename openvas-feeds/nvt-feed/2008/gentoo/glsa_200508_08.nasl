# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55091");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-2097");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Gentoo Security Advisory GLSA 200508-08 (xpdf kpdf gpdf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Xpdf, Kpdf and GPdf may crash as a result of a Denial of Service
vulnerability.");
  script_tag(name:"solution", value:"All Xpdf users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/xpdf-3.00-r10'

All GPdf users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/gpdf-2.10.0-r1'

All Kpdf users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdegraphics-3.3.2-r3'

All KDE Split Ebuild Kpdf users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kpdf-3.4.1-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200508-08");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14529");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=99769");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=100263");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=100265");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200508-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-text/xpdf", unaffected: make_list("ge 3.00-r10"), vulnerable: make_list("lt 3.00-r10"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kdegraphics", unaffected: make_list("ge 3.3.2-r3"), vulnerable: make_list("lt 3.3.2-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kpdf", unaffected: make_list("ge 3.4.1-r1"), vulnerable: make_list("lt 3.4.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-text/gpdf", unaffected: make_list("ge 2.10.0-r1"), vulnerable: make_list("lt 2.10.0-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
