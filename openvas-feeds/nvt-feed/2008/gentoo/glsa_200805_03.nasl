# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60941");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2008-1142", "CVE-2008-1692");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200805-03 (aterm eterm rxvt mrxvt multi-aterm wterm rxvt-unicode)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A vulnerability was found in aterm, Eterm, Mrxvt, multi-aterm, RXVT,
rxvt-unicode, and wterm, allowing for local privilege escalation.");
  script_tag(name:"solution", value:"All aterm users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/aterm-1.0.1-r1'

All Eterm users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/eterm-0.9.4-r1'

All Mrxvt users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/mrxvt-0.5.3-r2'

All multi-aterm users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/multi-aterm-0.2.1-r1'

All RXVT users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/rxvt-2.7.10-r4'

All rxvt-unicode users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/rxvt-unicode-9.02-r1'

All wterm users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-terms/wterm-6.2.9-r3'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200805-03");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=216833");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=217819");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=219746");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=219750");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=219754");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=219760");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=219762");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200805-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"x11-terms/aterm", unaffected: make_list("ge 1.0.1-r1"), vulnerable: make_list("lt 1.0.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/eterm", unaffected: make_list("ge 0.9.4-r1"), vulnerable: make_list("lt 0.9.4-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/mrxvt", unaffected: make_list("ge 0.5.3-r2"), vulnerable: make_list("lt 0.5.3-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/multi-aterm", unaffected: make_list("ge 0.2.1-r1"), vulnerable: make_list("lt 0.2.1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/rxvt", unaffected: make_list("ge 2.7.10-r4"), vulnerable: make_list("lt 2.7.10-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/rxvt-unicode", unaffected: make_list("ge 9.02-r1"), vulnerable: make_list("lt 9.02-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-terms/wterm", unaffected: make_list("ge 6.2.9-r3"), vulnerable: make_list("lt 6.2.9-r3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
