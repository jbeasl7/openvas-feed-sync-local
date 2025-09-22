# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55360");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-2871");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200509-11 (mozilla)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Mozilla Suite and Firefox are vulnerable to a buffer overflow that might be
exploited to execute arbitrary code.");
  script_tag(name:"solution", value:"All Mozilla Firefox users should upgrade to the latest version:

# emerge --sync
# emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-1.0.6-r7'

All Mozilla Suite users should upgrade to the latest version:

# emerge --sync
# emerge --ask --oneshot --verbose '>=www-client/mozilla-1.7.11-r3'

There are no fixed Mozilla Firefox or Mozilla Suite binaries yet. Users of
the mozilla-bin or mozilla-firefox-bin packages should either switch to
the source-based versions or apply the workaround.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200509-11");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14784");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=105396");
  script_xref(name:"URL", value:"https://addons.mozilla.org/messages/307259.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200509-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-client/mozilla-firefox", unaffected: make_list("ge 1.0.6-r7"), vulnerable: make_list("le 1.0.6-r6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/mozilla", unaffected: make_list("ge 1.7.11-r3"), vulnerable: make_list("le 1.7.11-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/mozilla-firefox-bin", unaffected: make_list(), vulnerable: make_list("le 1.0.6-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/mozilla-bin", unaffected: make_list(), vulnerable: make_list("le 1.7.11"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
