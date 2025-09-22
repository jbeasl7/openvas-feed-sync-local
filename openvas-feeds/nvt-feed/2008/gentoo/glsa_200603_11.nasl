# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56419");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2006-0047");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Gentoo Security Advisory GLSA 200603-11 (freeciv)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A memory allocation bug in Freeciv allows a remote attacker to perform a
Denial of Service attack.");
  script_tag(name:"solution", value:"All Freeciv users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=games-strategy/freeciv-2.0.8'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200603-11");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16975");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=125304");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/freecivdos-adv.txt");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200603-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"games-strategy/freeciv", unaffected: make_list("ge 2.0.8"), vulnerable: make_list("lt 2.0.8"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
