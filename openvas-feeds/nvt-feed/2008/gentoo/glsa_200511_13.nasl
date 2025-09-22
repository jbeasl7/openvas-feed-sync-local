# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55879");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-3354");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200511-13 (sylpheed sylpheed-claws)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Sylpheed and Sylpheed-Claws contain a buffer overflow vulnerability which
may lead to the execution of arbitrary code.");
  script_tag(name:"solution", value:"All Sylpheed users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/sylpheed-2.0.4'

All Sylpheed-Claws users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/sylpheed-claws-1.0.5-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200511-13");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15363");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=111853");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200511-13.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"mail-client/sylpheed", unaffected: make_list("ge 2.0.4"), vulnerable: make_list("lt 2.0.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/sylpheed-claws", unaffected: make_list("ge 1.0.5-r1"), vulnerable: make_list("lt 1.0.5-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
