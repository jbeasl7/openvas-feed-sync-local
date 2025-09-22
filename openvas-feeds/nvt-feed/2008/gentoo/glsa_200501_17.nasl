# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54803");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-1125");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200501-17 (kpdf, koffice)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"KPdf and KOffice both include vulnerable Xpdf code to handle PDF files,
making them vulnerable to the execution of arbitrary code if a user is
enticed to view a malicious PDF file.");
  script_tag(name:"solution", value:"All KPdf users should upgrade to the latest version of kdegraphics:

    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdegraphics

All KOffice users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose app-office/koffice");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200501-17");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=75203");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=75204");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200412-24.xml");
  script_xref(name:"URL", value:"http://kde.org/info/security/advisory-20041223-1.txt");
  script_xref(name:"URL", value:"http://koffice.kde.org/security/2004_xpdf_integer_overflow_2.php");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200501-17.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-office/koffice", unaffected: make_list("ge 1.3.5-r1"), vulnerable: make_list("lt 1.3.5-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kdegraphics", unaffected: make_list("ge 3.3.2-r1", "rge 3.2.3-r3"), vulnerable: make_list("lt 3.3.2-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
