# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55128");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-2498");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200508-14 (tikiwiki egroupware)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"TikiWiki and eGroupWare both include PHP XML-RPC code vulnerable to
arbitrary command execution.");
  script_tag(name:"solution", value:"All TikiWiki users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/tikiwiki-1.8.5-r2'

All eGroupWare users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/egroupware-1.0.0.009'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200508-14");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14560");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=102374");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=102377");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200508-14.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-apps/tikiwiki", unaffected: make_list("ge 1.8.5-r2"), vulnerable: make_list("lt 1.8.5-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/egroupware", unaffected: make_list("ge 1.0.0.009"), vulnerable: make_list("lt 1.0.0.009"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
