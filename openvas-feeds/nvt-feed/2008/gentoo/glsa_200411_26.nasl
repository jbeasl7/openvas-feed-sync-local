# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54747");
  script_cve_id("CVE-2004-1115", "CVE-2004-1116", "CVE-2004-1117");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200411-26 (GIMPS, SETI@home, ChessBrain)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Improper file ownership allows user-owned files to be run with root
privileges by init scripts.");
  script_tag(name:"solution", value:"All GIMPS users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-sci/gimps-23.9-r1'

All SETI@home users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-sci/setiathome-3.03-r2'

All ChessBrain users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-sci/chessbrain-20407-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200411-26");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=69868");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200411-26.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-sci/gimps", unaffected: make_list("ge 23.9-r1"), vulnerable: make_list("le 23.9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-sci/setiathome", unaffected: make_list("ge 3.08-r4", "rge 3.03-r2"), vulnerable: make_list("le 3.08-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-sci/chessbrain", unaffected: make_list("ge 20407-r1"), vulnerable: make_list("le 20407"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
