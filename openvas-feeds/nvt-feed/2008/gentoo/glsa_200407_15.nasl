# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54622");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Gentoo Security Advisory GLSA 200407-15 (opera)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Opera contains three vulnerabilities, allowing an attacker to impersonate
legitimate websites with URI obfuscation or to spoof websites with frame
injection.");
  script_tag(name:"solution", value:"All Opera users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '>=net-www/opera-7.53'
    # emerge '>=net-www/opera-7.53'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200407-15");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=56311");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=56109");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10517");
  script_xref(name:"URL", value:"http://secunia.com/advisories/11978/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/12028/");
  script_xref(name:"URL", value:"http://www.opera.com/linux/changelogs/753/");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200407-15.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/opera", unaffected: make_list("ge 7.53"), vulnerable: make_list("le 7.52"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
