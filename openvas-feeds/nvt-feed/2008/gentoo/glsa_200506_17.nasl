# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54969");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-1266");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Gentoo Security Advisory GLSA 200506-17 (SpamAssassin, Vipul's Razor)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"SpamAssassin and Vipul's Razor are vulnerable to a Denial of Service attack
when handling certain malformed messages.");
  script_tag(name:"solution", value:"All SpamAssassin users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-filter/spamassassin-3.0.4'

All Vipul's Razor users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-filter/razor-2.74'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200506-17");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=94722");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=95492");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=96776");
  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/spamassassin-announce/200506.mbox/%3c17072.35054.586017.822288@proton.pathname.com%3e");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/forum.php?thread_id=7520323&forum_id=4259");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200506-17.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"mail-filter/spamassassin", unaffected: make_list("ge 3.0.4", "lt 3.0.1"), vulnerable: make_list("lt 3.0.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-filter/razor", unaffected: make_list("ge 2.74"), vulnerable: make_list("lt 2.74"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
