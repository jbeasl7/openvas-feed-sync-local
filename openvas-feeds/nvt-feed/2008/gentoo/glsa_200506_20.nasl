# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54972");
  script_cve_id("CVE-2005-1524", "CVE-2005-1525", "CVE-2005-1526");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200506-20 (cacti)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Cacti is vulnerable to several SQL injection, authentication bypass and
file inclusion vulnerabilities.");
  script_tag(name:"solution", value:"All Cacti users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/cacti-0.8.6f'

Note: Users with the vhosts USE flag set should manually use webapp-config
to finalize the update.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200506-20");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=96243");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=97475");
  script_xref(name:"URL", value:"http://www.cacti.net/release_notes_0_8_6e.php");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=267&type=vulnerabilities&flashstatus=false");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=266&type=vulnerabilities&flashstatus=false");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=265&type=vulnerabilities&flashstatus=false");
  script_xref(name:"URL", value:"http://www.cacti.net/release_notes_0_8_6f.php");
  script_xref(name:"URL", value:"http://www.hardened-php.net/advisory-032005.php");
  script_xref(name:"URL", value:"http://www.hardened-php.net/advisory-042005.php");
  script_xref(name:"URL", value:"http://www.hardened-php.net/advisory-052005.php");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200506-20.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-analyzer/cacti", unaffected: make_list("ge 0.8.6f"), vulnerable: make_list("lt 0.8.6f"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
