# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56246");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-3352", "CVE-2005-3357");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_name("Gentoo Security Advisory GLSA 200602-03 (Apache)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Apache can be exploited for cross-site scripting attacks and is vulnerable
to a Denial of Service attack.");
  script_tag(name:"solution", value:"All Apache users should upgrade to the latest version, depending on whether
they still use the old configuration style (/etc/apache/conf/*.conf) or the
new one (/etc/apache2/httpd.conf).

2.0.x users, new style config:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-www/apache-2.0.55-r1'

2.0.x users, old style config:

    # emerge --sync
    # emerge --ask --oneshot --verbose '=net-www/apache-2.0.54-r16'

1.x users, new style config:

    # emerge --sync
    # emerge --ask --oneshot --verbose '=net-www/apache-1.3.34-r11'

1.x users, old style config:

    # emerge --sync
    # emerge --ask --oneshot --verbose '=net-www/apache-1.3.34-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200602-03");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=115324");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=118875");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200602-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/apache", unaffected: make_list("ge 2.0.55-r1", "rge 2.0.54-r16", "eq 1.3.34-r2", "rge 1.3.34-r11"), vulnerable: make_list("lt 2.0.55-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
