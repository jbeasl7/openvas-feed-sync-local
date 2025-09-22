# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54498");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2003-0542");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200310-03 (Apache)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple stack-based buffer overflows in mod_alias and mod_rewrite can
allow execution of arbitrary code and cause a denial of service.");
  script_tag(name:"solution", value:"It is recommended that all Gentoo Linux users who are running
net-misc/apache 1.x upgrade:

    # emerge sync
    # emerge -pv apache
    # emerge '>=net-www/apache-1.3.29'
    # emerge clean
    # /etc/init.d/apache restart");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200310-03");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8911");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9504");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=32194");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200310-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/apache", unaffected: make_list("ge 1.3.29"), vulnerable: make_list("lt 1.3.29"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
