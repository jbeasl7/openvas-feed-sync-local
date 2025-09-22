# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54584");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0433");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200405-24 (mplayer)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities, including remotely exploitable buffer overflows,
have been found in code common to MPlayer and the xine library.");
  script_tag(name:"solution", value:"All users should upgrade to non-vulnerable versions of MPlayer and
xine-lib:

    # emerge sync

    # emerge -pv '>=media-video/mplayer-1.0_pre4'
    # emerge '>=media-video/mplayer-1.0_pre4'

    # emerge -pv '>=media-libs/xine-lib-1_rc4'
    # emerge '>=media-libs/xine-lib-1_rc4'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200405-24");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=49387");
  script_xref(name:"URL", value:"http://xinehq.de/index.php/security/XSA-2004-3");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200405-24.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"media-video/mplayer", unaffected: make_list("ge 1.0_pre4", "le 0.92-r1"), vulnerable: make_list("lt 1.0_pre4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-libs/xine-lib", unaffected: make_list("ge 1_rc4", "le 0.9.13-r3"), vulnerable: make_list("lt 1_rc4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
