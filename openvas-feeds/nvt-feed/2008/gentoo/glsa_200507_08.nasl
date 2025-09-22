# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54984");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-1921");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200507-08 (phpgroupware egroupware)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"phpGroupWare and eGroupWare include an XML-RPC implementation which allows
remote attackers to execute arbitrary PHP script commands.");
  script_tag(name:"solution", value:"All phpGroupWare users should upgrade to the latest available version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-app/phpgroupware-0.9.16.006'

All eGroupWare users should upgrade to the latest available version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-app/egroupware-1.0.0.008'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200507-08");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14088");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=97460");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=97651");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200507-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-apps/phpgroupware", unaffected: make_list("ge 0.9.16.006"), vulnerable: make_list("lt 0.9.16.006"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/egroupware", unaffected: make_list("ge 1.0.0.008"), vulnerable: make_list("lt 1.0.0.008"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
