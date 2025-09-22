# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58301");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200705-23 (sun-jdk, sun-jre-bin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been identified in Sun Java Development Kit
(JDK) and Java Runtime Environment (JRE).");
  script_tag(name:"solution", value:"All Sun Java Development Kit users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose 'dev-java/sun-jdk'

All Sun Java Runtime Environment users should upgrade to the latest
version:

    # emerge --sync
    # emerge --ask --oneshot --verbose 'dev-java/sun-jre-bin'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200705-23");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=176675");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=178851");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200705-23.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-java/sun-jdk", unaffected: make_list("ge 1.5.0.11", "rge 1.4.2.14"), vulnerable: make_list("lt 1.5.0.11"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-java/sun-jre-bin", unaffected: make_list("rge 1.5.0.11", "rge 1.4.2.14", "ge 1.6.0.01"), vulnerable: make_list("lt 1.6.0.01"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
