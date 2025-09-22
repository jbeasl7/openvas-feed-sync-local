# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69025");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2369");
  script_name("Gentoo Security Advisory GLSA 201009-01 (wxGTK)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"An integer overflow vulnerability in wxGTK might enable remote attackers to
    cause the execution of arbitrary code.");
  script_tag(name:"solution", value:"All wxGTK 2.6 users should upgrade to an updated version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/wxGTK-2.6.4.0-r5'

All wxGTK 2.8 users should upgrade to an updated version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/wxGTK-2.8.10.1-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201009-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=277722");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201009-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"x11-libs/wxGTK", unaffected: make_list("rge 2.6.4.0-r5", "ge 2.8.10.1-r1"), vulnerable: make_list("lt 2.8.10.1-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
