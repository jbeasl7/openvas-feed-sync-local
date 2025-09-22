# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54519");
  script_cve_id("CVE-2004-0263");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200402-01 (PHP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"If the server configuration ' php.ini ' file has ' register_globals = on '
and a request is made to one virtual host (which has ' php_admin_flag
register_globals off ' ) and the next request is sent to the another
virtual host (which does not have the setting) global variables may leak
and may be used to exploit the site.");
  script_tag(name:"solution", value:"All users are recommended to upgrade their PHP installation to 4.3.4-r4:

    # emerge sync
    # emerge -pv '>=dev-php/mod_php-4.3.4-r4'
    # emerge '>=dev-php/mod_php-4.3.4-r4'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200402-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=39952");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=25753");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200402-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-php/mod_php", unaffected: make_list("ge 4.3.4-r4"), vulnerable: make_list("lt 4.3.4-r4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
