# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54512");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Gentoo Security Advisory GLSA 200312-06 (xchat)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A bug in XChat could allow malformed dcc send requests to cause a denial of
service.");
  script_tag(name:"solution", value:"For Gentoo users, xchat-2.0.6 was marked ~arch (unstable) for most
architectures.  Since it was never marked as stable in the portage tree,
only xchat users who have explicitly added the unstable keyword to
ACCEPT_KEYWORDS are affected.  Users may updated affected machines to the
patched version of xchat using the following commands:

    # emerge sync
    # emerge -pv '>=net-irc/xchat-2.0.6-r1'
    # emerge '>=net-irc/xchat-2.0.6-r1'
    # emerge clean

This assumes that users are running with ACCEPT_KEYWORDS enabled for their
architecture.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200312-06");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=35623");
  script_xref(name:"URL", value:"http://mail.nl.linux.org/xchat-announce/2003-12/msg00000.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200312-06.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-irc/xchat", unaffected: make_list("ge 2.0.6-r1"), vulnerable: make_list("eq 2.0.6"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
