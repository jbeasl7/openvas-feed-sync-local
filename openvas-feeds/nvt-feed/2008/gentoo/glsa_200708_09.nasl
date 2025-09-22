# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58544");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738", "CVE-2007-3844");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200708-09 (mozilla/thunderbird/firefox/xulrunner)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported in Mozilla Firefox,
Thunderbird, SeaMonkey and XULRunner, some of which may allow
user-assisted arbitrary remote code execution.

For details on the issues addressed with this update,
please visit the referenced security advisories.");
  script_tag(name:"solution", value:"Apply the appropriate updates.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200708-09");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=185737");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=187205");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200708-09.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-client/mozilla-firefox", unaffected: make_list("ge 2.0.0.6"), vulnerable: make_list("lt 2.0.0.6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/mozilla-firefox-bin", unaffected: make_list("ge 2.0.0.6"), vulnerable: make_list("lt 2.0.0.6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird", unaffected: make_list("ge 2.0.0.6"), vulnerable: make_list("lt 2.0.0.6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 2.0.0.6"), vulnerable: make_list("lt 2.0.0.6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/seamonkey", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/seamonkey-bin", unaffected: make_list("ge 1.1.4"), vulnerable: make_list("lt 1.1.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-libs/xulrunner", unaffected: make_list("ge 1.8.1.6"), vulnerable: make_list("lt 1.8.1.6"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
