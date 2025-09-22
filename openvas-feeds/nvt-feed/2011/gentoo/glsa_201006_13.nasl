# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69016");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-1066", "CVE-2008-4810", "CVE-2008-4811", "CVE-2009-1669");
  script_name("Gentoo Security Advisory GLSA 201006-13 (smarty)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in the Smarty template engine might allow remote
    attackers to execute arbitrary PHP code.");
  script_tag(name:"solution", value:"All Smarty users should upgrade to an unaffected version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/smarty-2.6.23'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201006-13");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=212147");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=243856");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=270494");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201006-13.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-php/smarty", unaffected: make_list("ge 2.6.23"), vulnerable: make_list("lt 2.6.23"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
