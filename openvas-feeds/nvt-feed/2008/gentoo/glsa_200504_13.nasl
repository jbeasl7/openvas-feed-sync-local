# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54915");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-0941");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200504-13 (OpenOffice)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"OpenOffice.Org is vulnerable to a heap overflow when processing DOC
documents, which could lead to arbitrary code execution.");
  script_tag(name:"solution", value:"All OpenOffice.Org users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-1.1.4-r1'

All OpenOffice.Org binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=app-office/openoffice-bin-1.1.4-r1'

All OpenOffice.Org Ximian users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose app-office/openoffice-ximian

Note to PPC users: There is no stable OpenOffice.Org fixed version for the
PPC architecture. Affected users should switch to the latest
OpenOffice.Org Ximian version.

Note to SPARC users: There is no stable OpenOffice.Org fixed version for
the SPARC architecture. Affected users should switch to the latest
OpenOffice.Org Ximian version.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200504-13");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13092");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=88863");
  script_xref(name:"URL", value:"http://www.openoffice.org/issues/show_bug.cgi?id=46388");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200504-13.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 1.1.4-r1"), vulnerable: make_list("lt 1.1.4-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-bin", unaffected: make_list("ge 1.1.4-r1"), vulnerable: make_list("lt 1.1.4-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-ximian", unaffected: make_list("ge 1.3.9-r1", "rge 1.3.6-r1", "rge 1.3.7-r1"), vulnerable: make_list("lt 1.3.9-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
