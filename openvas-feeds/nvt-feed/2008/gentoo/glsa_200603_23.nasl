# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56551");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2006-1390");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200603-23 (nethack slashem falconseye)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"NetHack, Slash'EM and Falcon's Eye are vulnerable to local privilege
escalation vulnerabilities that could potentially allow the execution of
arbitrary code as other users.");
  script_tag(name:"solution", value:"NetHack has been masked in Portage pending the resolution of these issues.
Vulnerable NetHack users are advised to uninstall the package until
further notice.

    # emerge --ask --verbose --unmerge 'games-roguelike/nethack'

Slash'EM has been masked in Portage pending the resolution of these
issues. Vulnerable Slash'EM users are advised to uninstall the package
until further notice.

    # emerge --ask --verbose --unmerge 'games-roguelike/slashem'

Falcon's Eye has been masked in Portage pending the resolution of these
issues. Vulnerable Falcon's Eye users are advised to uninstall the package
until further notice.

    # emerge --ask --verbose --unmerge 'games-roguelike/falconseye'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200603-23");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17217");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=125902");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=122376");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=127167");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=127319");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200603-23.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"games-roguelike/nethack", unaffected: make_list(), vulnerable: make_list("le 3.4.3-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"games-roguelike/falconseye", unaffected: make_list(), vulnerable: make_list("le 1.9.4a"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"games-roguelike/slashem", unaffected: make_list(), vulnerable: make_list("le 0.0.760"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
