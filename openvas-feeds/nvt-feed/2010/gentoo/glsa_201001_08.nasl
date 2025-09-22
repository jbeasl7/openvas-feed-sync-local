# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66741");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-20 20:07:43 +0100 (Wed, 20 Jan 2010)");
  script_cve_id("CVE-2009-1381", "CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580", "CVE-2009-1581");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 201001-08 (squirrelmail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in SquirrelMail of which the worst
    results in remote code execution.");
  script_tag(name:"solution", value:"All SquirrelMail users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/squirrelmail-1.4.19'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201001-08");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=269567");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=270671");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201001-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"mail-client/squirrelmail", unaffected: make_list("ge 1.4.19"), vulnerable: make_list("lt 1.4.19"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
