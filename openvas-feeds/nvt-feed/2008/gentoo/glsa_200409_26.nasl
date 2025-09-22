# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54682");
  script_cve_id("CVE-2004-0902", "CVE-2004-0903", "CVE-2004-0904", "CVE-2004-0905", "CVE-2004-0906", "CVE-2004-0907", "CVE-2004-0908", "CVE-2004-0909");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200409-26 (Mozilla)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"New releases of Mozilla, Epiphany, Mozilla Thunderbird, and Mozilla Firefox
fix several vulnerabilities, including the remote execution of arbitrary
code.");
  script_tag(name:"solution", value:"All users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv your-version
    # emerge your-version");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-26");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=63996");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla1.7.3");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA04-261A.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200409-26.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/mozilla", unaffected: make_list("ge 1.7.3"), vulnerable: make_list("lt 1.7.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-firefox", unaffected: make_list("ge 1.0_pre"), vulnerable: make_list("lt 1.0_pre"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird", unaffected: make_list("ge 0.8"), vulnerable: make_list("lt 0.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-bin", unaffected: make_list("ge 1.7.3"), vulnerable: make_list("lt 1.7.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/mozilla-firefox-bin", unaffected: make_list("ge 1.0_pre"), vulnerable: make_list("lt 1.0_pre"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 0.8"), vulnerable: make_list("lt 0.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/epiphany", unaffected: make_list("ge 1.2.9-r1"), vulnerable: make_list("lt 1.2.9-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
