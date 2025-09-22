# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54520");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0083");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200402-02 (200402-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Exploitation of a buffer overflow in the XFree86 Project Inc.'s XFree86 X
Window System allows local attackers to gain root privileges.");
  script_tag(name:"solution", value:"All users are recommended to upgrade their XFree86 installation:

    # emerge sync
    # emerge -pv x11-base/xfree
    # emerge x11-base/xfree");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200402-02");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9636");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=72&type=vulnerabilities");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200402-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"x11-base/xfree", unaffected: make_list("eq 4.2.1-r3", "eq 4.3.0-r4", "ge 4.3.99.902-r1"), vulnerable: make_list("lt 4.3.99.902-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
