# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58699");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-3387");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200710-20 (pdfkit imagekits)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"PDFKit and ImageKits are vulnerable to an integer overflow and a stack
overflow allowing for the user-assisted execution of arbitrary code.");
  script_tag(name:"solution", value:"PDFKit and ImageKits are not maintained upstream, so the packages were
masked in Portage. We recommend that users unmerge PDFKit and ImageKits:

    # emerge --unmerge gnustep-libs/pdfkit
    # emerge --unmerge gnustep-libs/imagekits

As an alternative, users should upgrade their systems to use PopplerKit
instead of PDFKit and Vindaloo instead of ViewPDF.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200710-20");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=188185");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200709-12.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200710-20.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"gnustep-libs/pdfkit", unaffected: make_list(), vulnerable: make_list("le 0.9_pre062906"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"gnustep-libs/imagekits", unaffected: make_list(), vulnerable: make_list("le 0.6"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
