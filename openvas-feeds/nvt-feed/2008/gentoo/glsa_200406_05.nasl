# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54590");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0488");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200406-05 (Apache)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A bug in mod_ssl may allow a remote attacker to execute remote code when
Apache is configured a certain way.");
  script_tag(name:"solution", value:"Apache 1.x users should upgrade to the latest version of mod_ssl:

    # emerge sync

    # emerge -pv '>=net-www/mod_ssl-2.8.18'
    # emerge '>=net-www/mod_ssl-2.8.18'

Apache 2.x users should upgrade to the latest version of Apache:

    # emerge sync

    # emerge -pv '>=net-www/apache-2.0.49-r3'
    # emerge '>=net-www/apache-2.0.49-r3'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200406-05");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10355");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=51368");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200406-05.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/mod_ssl", unaffected: make_list("ge 2.8.18"), vulnerable: make_list("lt 2.8.18"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-www/apache", unaffected: make_list("lt 2.0", "ge 2.0.49-r3"), vulnerable: make_list("le 2.0.49-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
