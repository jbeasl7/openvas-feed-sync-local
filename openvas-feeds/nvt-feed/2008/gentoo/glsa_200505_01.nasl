# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54933");
  script_version("2023-07-18T05:05:36+0000");
  script_cve_id("CVE-2005-1313", "CVE-2005-1314", "CVE-2005-1315", "CVE-2005-1316", "CVE-2005-1317",
                "CVE-2005-1318", "CVE-2005-1319", "CVE-2005-1320", "CVE-2005-1321", "CVE-2005-1322");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200505-01 (Horde)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");

  script_tag(name:"insight", value:"Various modules of the Horde Framework are vulnerable to multiple
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"solution", value:"All Horde Framework users should upgrade to the latest version:

  # emerge --sync

  - Horde: # emerge --ask --oneshot --verbose '>=www-apps/horde-2.2.8'

  - Horde Vacation: # emerge --ask --oneshot --verbose '>=www-apps/horde-vacation-2.2.2'

  - Horde Turba: # emerge --ask --oneshot --verbose '>=www-apps/horde-turba-1.2.5'

  - Horde Passwd: # emerge --ask --oneshot --verbose '>=www-apps/horde-passwd-2.2.2'

  - Horde Nag: # emerge --ask --oneshot --verbose '>=www-apps/horde-nag-1.1.3'

  - Horde Mnemo: # emerge --ask --oneshot --verbose '>=www-apps/horde-mnemo-1.1.4'

  - Horde Kronolith: # emerge --ask --oneshot --verbose '>=www-apps/horde-kronolith-1.1.4'

  - Horde IMP: # emerge --ask --oneshot --verbose '>=www-apps/horde-imp-3.2.8'

  - Horde Accounts: # emerge --ask --oneshot --verbose '>=www-apps/horde-accounts-2.1.2'

  - Horde Forwards: # emerge --ask --oneshot --verbose '>=www-apps/horde-forwards-2.2.2'

  - Horde Chora: # emerge --ask --oneshot --verbose '>=www-apps/horde-chora-1.2.3'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200505-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=90365");
  script_xref(name:"URL", value:"http://marc.info/?l=horde-announce&r=1&b=200504&w=2");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
  advisory GLSA 200505-01.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";

if ((res = ispkgvuln(pkg:"www-apps/horde-vacation", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-turba", unaffected: make_list("ge 1.2.5"), vulnerable: make_list("lt 1.2.5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-passwd", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-nag", unaffected: make_list("ge 1.1.3"), vulnerable: make_list("lt 1.1.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-mnemo", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-kronolith", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-imp", unaffected: make_list("ge 3.2.8"), vulnerable: make_list("lt 3.2.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-accounts", unaffected: make_list("ge 2.1.2"), vulnerable: make_list("lt 2.1.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-forwards", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-chora", unaffected: make_list("ge 1.2.3"), vulnerable: make_list("lt 1.2.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde", unaffected: make_list("ge 2.2.8"), vulnerable: make_list("lt 2.2.8"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
