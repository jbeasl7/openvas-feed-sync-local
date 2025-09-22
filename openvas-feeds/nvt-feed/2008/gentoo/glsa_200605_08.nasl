# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56723");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2006-0996", "CVE-2006-1490", "CVE-2006-1990", "CVE-2006-1991");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200605-08 (php)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"PHP is affected by multiple issues, including a buffer overflow in
wordwrap() which may lead to execution of arbitrary code.");
  script_tag(name:"solution", value:"All PHP users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-lang/php-5.1.4'

PHP4 users that wish to keep that version line should upgrade to the
latest 4.x version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =dev-lang/php-4.4.2-r2");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200605-08");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=127939");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=128883");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=131135");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200605-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-lang/php", unaffected: make_list("ge 5.1.4", "rge 4.4.2-r2"), vulnerable: make_list("lt 5.1.4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
