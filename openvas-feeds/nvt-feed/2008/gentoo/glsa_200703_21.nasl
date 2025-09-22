# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58159");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2006-5465", "CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0911", "CVE-2007-0988", "CVE-2007-1286", "CVE-2007-1375", "CVE-2007-1376", "CVE-2007-1380", "CVE-2007-1383");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200703-21 (php)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"PHP contains several vulnerabilities including a heap buffer overflow,
potentially leading to the remote execution of arbitrary code under
certain conditions.");
  script_tag(name:"solution", value:"All PHP users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose 'dev-lang/php'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200703-21");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=153911");
  script_xref(name:"URL", value:"http://www.php.net/releases/4_4_5.php");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_1.php");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200703-21.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-lang/php", unaffected: make_list("ge 5.2.1-r3", "rge 5.1.6-r11", "rge 4.4.6"), vulnerable: make_list("lt 5.2.1-r3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
