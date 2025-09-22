# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54721");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0888", "CVE-2004-0889");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200410-30 (GPdf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"GPdf, KPDF and KOffice all include vulnerable xpdf code to handle PDF
files, making them vulnerable to execution of arbitrary code upon viewing
a malicious PDF file.");
  script_tag(name:"solution", value:"All GPdf users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/gpdf-0.132-r2'

All KDE users should upgrade to the latest version of kdegraphics:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdegraphics-3.3.0-r2'

All KOffice users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/koffice-1.3.3-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200410-30");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=68558");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=68665");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=68571");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=69936");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=69624");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200410-20.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200410-30.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-office/koffice", unaffected: make_list("ge 1.3.4-r1", "rge 1.3.3-r2"), vulnerable: make_list("lt 1.3.4-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-text/gpdf", unaffected: make_list("ge 2.8.0-r2", "rge 0.132-r2"), vulnerable: make_list("lt 2.8.0-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kdegraphics", unaffected: make_list("ge 3.3.1-r2", "rge 3.3.0-r2", "rge 3.2.3-r2"), vulnerable: make_list("lt 3.3.1-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
