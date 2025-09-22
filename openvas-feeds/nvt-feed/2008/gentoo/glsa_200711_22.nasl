# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.59242");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200711-22 (poppler koffice kword kdegraphics kpdf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Poppler and various KDE components are vulnerable to multiple memory
management issues possibly resulting in the execution of arbitrary code.");
  script_tag(name:"solution", value:"All Poppler users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/poppler-0.6.1-r1'

All KPDF users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kpdf-3.5.7-r3'

All KDE Graphics Libraries users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdegraphics-3.5.7-r3'

All KWord users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/kword-1.6.3-r2'

All KOffice users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/koffice-1.6.3-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200711-22");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=196735");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=198409");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200711-22.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-text/poppler", unaffected: make_list("ge 0.6.1-r1"), vulnerable: make_list("lt 0.6.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kpdf", unaffected: make_list("rge 3.5.7-r3", "ge 3.5.8-r1"), vulnerable: make_list("lt 3.5.8-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kdegraphics", unaffected: make_list("rge 3.5.7-r3", "ge 3.5.8-r1"), vulnerable: make_list("lt 3.5.8-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/kword", unaffected: make_list("ge 1.6.3-r2"), vulnerable: make_list("lt 1.6.3-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/koffice", unaffected: make_list("ge 1.6.3-r2"), vulnerable: make_list("lt 1.6.3-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
