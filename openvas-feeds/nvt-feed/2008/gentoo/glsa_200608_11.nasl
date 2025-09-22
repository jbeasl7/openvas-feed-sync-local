# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57861");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2006-3392");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Gentoo Security Advisory GLSA 200608-11 (webmin/usermin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Webmin and Usermin are vulnerable to an arbitrary file disclosure through a
specially crafted URL.");
  script_tag(name:"solution", value:"All Webmin users should update to the latest stable version:

    # emerge --sync
    # emerge --ask --verbose --oneshot '>=app-admin/webmin-1.290'

All Usermin users should update to the latest stable version:

    # emerge --sync
    # emerge --ask --verbose --oneshot '>=app-admin/usermin-1.220'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200608-11");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=138552");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200608-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-admin/webmin", unaffected: make_list("ge 1.290"), vulnerable: make_list("lt 1.290"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-admin/usermin", unaffected: make_list("ge 1.220"), vulnerable: make_list("lt 1.220"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
