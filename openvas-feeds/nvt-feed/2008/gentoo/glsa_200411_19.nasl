# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54740");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0456");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200411-19 (pavuk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Pavuk contains multiple buffer overflows that can allow a remote attacker
to run arbitrary code.");
  script_tag(name:"solution", value:"All Pavuk users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/pavuk-0.9.31'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200411-19");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10633");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=70516");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200407-19.xml");
  script_xref(name:"URL", value:"http://secunia.com/advisories/13120/");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200411-19.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-misc/pavuk", unaffected: make_list("ge 0.9.31"), vulnerable: make_list("lt 0.9.31"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
