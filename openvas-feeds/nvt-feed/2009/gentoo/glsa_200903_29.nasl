# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63613");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
  script_cve_id("CVE-2008-2374");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200903-29 (bluez-utils bluez-libs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Insufficient input validation in BlueZ may lead to arbitrary code execution
or a Denial of Service.");
  script_tag(name:"solution", value:"All bluez-utils users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-wireless/bluez-utils-3.36'

All bluez-libs users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-wireless/bluez-libs-3.36'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200903-29");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=230591");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200903-29.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-wireless/bluez-utils", unaffected: make_list("ge 3.36"), vulnerable: make_list("lt 3.36"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-wireless/bluez-libs", unaffected: make_list("ge 3.36"), vulnerable: make_list("lt 3.36"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
