# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54538");
  script_cve_id("CVE-2004-0386");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200403-13 (mplayer)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"MPlayer contains a remotely exploitable buffer overflow in the HTTP parser
that may allow attackers to run arbitrary code on a user's computer.");
  script_tag(name:"solution", value:"MPlayer may be upgraded as follows:

x86 and SPARC users should:

    # emerge sync

    # emerge -pv '>=media-video/mplayer-0.92-r1'
    # emerge '>=media-video/mplayer-0.92-r1'

AMD64 users should:

    # emerge sync

    # emerge -pv '>=media-video/mplayer-1.0_pre2-r1'
    # emerge '>=media-video/mplayer-1.0_pre2-r1'

PPC users should:

    # emerge sync

    # emerge -pv '>=media-video/mplayer-1.0_pre3-r2'
    # emerge '>=media-video/mplayer-1.0_pre3-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200403-13");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=46246");
  script_xref(name:"URL", value:"http://www.mplayerhq.hu/homepage/design6/news.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200403-13.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"media-video/mplayer", unaffected: make_list("ge 0.92-r1"), vulnerable: make_list("le 0.92"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-video/mplayer", unaffected: make_list("ge 1.0_pre2-r1"), vulnerable: make_list("le 1.0_pre2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-video/mplayer", unaffected: make_list("ge 1.0_pre3-r3"), vulnerable: make_list("le 1.0_pre3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
