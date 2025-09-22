# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63805");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2008-5397", "CVE-2008-5398", "CVE-2009-0414", "CVE-2009-0936", "CVE-2009-0937", "CVE-2009-0938", "CVE-2009-0939");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200904-11 (tor)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in Tor might allow for heap corruption, Denial of
Service, escalation of privileges and information disclosure.");
  script_tag(name:"solution", value:"All Tor users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/tor-0.2.0.34'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200904-11");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=250018");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=256078");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=258833");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200904-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-misc/tor", unaffected: make_list("ge 0.2.0.34"), vulnerable: make_list("lt 0.2.0.34"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
