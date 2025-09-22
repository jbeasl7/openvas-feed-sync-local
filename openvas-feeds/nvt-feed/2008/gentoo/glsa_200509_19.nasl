# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55501");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-2491", "CVE-2005-2498");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200509-19 (PHP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"PHP makes use of an affected PCRE library and ships with an affected
XML-RPC library and is therefore potentially vulnerable to remote
execution of arbitrary code.");
  script_tag(name:"solution", value:"All PHP users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/php

All mod_php users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/mod_php

All php-cgi users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/php-cgi");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200509-19");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=102373");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200508-13.xml");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200508-17.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200509-19.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-php/php", unaffected: make_list("rge 4.3.11-r1", "ge 4.4.0-r1"), vulnerable: make_list("lt 4.4.0-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-php/mod_php", unaffected: make_list("rge 4.3.11-r1", "ge 4.4.0-r2"), vulnerable: make_list("lt 4.4.0-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-php/php-cgi", unaffected: make_list("rge 4.3.11-r2", "ge 4.4.0-r2"), vulnerable: make_list("lt 4.4.0-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
