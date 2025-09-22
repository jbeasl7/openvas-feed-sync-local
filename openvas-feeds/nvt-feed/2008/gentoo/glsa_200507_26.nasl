# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55002");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-1852");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200507-26 (gnugadu centericq kadu ekg libgadu)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"GNU Gadu, CenterICQ, Kadu, EKG and libgadu are vulnerable to an integer
overflow which could potentially lead to the execution of arbitrary code
or a Denial of Service.");
  script_tag(name:"solution", value:"All GNU Gadu users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/gnugadu-2.2.6-r1'

All Kadu users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/kadu-0.4.1'

All EKG users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/ekg-1.6_rc3'

All libgadu users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/libgadu-20050719'

All CenterICQ users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/centericq-4.20.0-r3'

CenterICQ is no longer distributed with Gadu Gadu support, affected users
are encouraged to migrate to an alternative package.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200507-26");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14345");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=99816");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=99890");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=99583");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/406026/30/");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200507-26.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-im/gnugadu", unaffected: make_list("ge 2.2.6-r1"), vulnerable: make_list("lt 2.2.6-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-im/centericq", unaffected: make_list("ge 4.20.0-r3"), vulnerable: make_list("lt 4.20.0-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-im/kadu", unaffected: make_list("ge 0.4.1"), vulnerable: make_list("lt 0.4.1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-im/ekg", unaffected: make_list("ge 1.6_rc3"), vulnerable: make_list("lt 1.6_rc3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-libs/libgadu", unaffected: make_list("ge 20050719"), vulnerable: make_list("lt 20050719"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
