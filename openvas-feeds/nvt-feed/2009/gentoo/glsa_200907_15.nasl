# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64437");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2008-5027", "CVE-2008-5028", "CVE-2008-6373", "CVE-2009-2288");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200907-15 (nagios-core)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in Nagios may lead to the execution of arbitrary
code.");
  script_tag(name:"solution", value:"All Nagios users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/nagios-core-3.0.6-r2'

NOTE: Users of the Nagios 2 branch can update to version 2.12-r1 which
    contains a patch to fix CVE-2009-2288. However, that branch is not
    supported upstream or in Gentoo and we are unaware whether the other
    vulnerabilities affect 2.x installations.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200907-15");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=245887");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=249876");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=275288");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200907-15.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-analyzer/nagios-core", unaffected: make_list("ge 3.0.6-r2"), vulnerable: make_list("lt 3.0.6-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
