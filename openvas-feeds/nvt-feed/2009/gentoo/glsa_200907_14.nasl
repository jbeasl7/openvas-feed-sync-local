# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64436");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-1760");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200907-14 (rb_libtorrent deluge)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A directory traversal vulnerability in Rasterbar libtorrent might allow a
remote attacker to overwrite arbitrary files.");
  script_tag(name:"solution", value:"All Rasterbar libtorrent users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/rb_libtorrent-0.13-r1'

All Deluge users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-p2p/deluge-1.1.9'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200907-14");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=273156");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=273961");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200907-14.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-libs/rb_libtorrent", unaffected: make_list("ge 0.13-r1"), vulnerable: make_list("lt 0.13-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-p2p/deluge", unaffected: make_list("ge 1.1.9"), vulnerable: make_list("lt 1.1.9"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
