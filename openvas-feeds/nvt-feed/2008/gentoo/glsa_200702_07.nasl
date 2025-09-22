# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58024");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-0243");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200702-07 (java)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Sun Java Development Kit (JDK) and Java Runtime Environment (JRE) contain a
memory corruption flaw that allows the applets to gain elevated privileges
potentially leading to the execute of arbitrary code.");
  script_tag(name:"solution", value:"All Sun Java Development Kit 1.5 users should upgrade to the latest
version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jdk-1.5.0.10'

All Sun Java Development Kit 1.4 users should upgrade to the latest
version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '=dev-java/sun-jdk-1.4.2*'

All Sun Java Runtime Environment 1.5 users should upgrade to the latest
version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/sun-jre-bin-1.5.0.10'

All Sun Java Runtime Environment 1.4 users should upgrade to the latest
version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '=dev-java/sun-jre-bin-1.4.2*'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200702-07");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=162511");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200702-07.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-java/sun-jdk", unaffected: make_list("ge 1.5.0.10", "rge 1.4.2.13"), vulnerable: make_list("lt 1.5.0.10", "lt 1.4.2.13"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-java/sun-jre-bin", unaffected: make_list("ge 1.5.0.10", "rge 1.4.2.13"), vulnerable: make_list("lt 1.5.0.10", "lt 1.4.2.13"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
