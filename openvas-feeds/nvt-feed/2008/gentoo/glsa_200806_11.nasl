# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61215");
  script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3655", "CVE-2007-5232", "CVE-2007-5237", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274", "CVE-2007-5689", "CVE-2008-0628", "CVE-2008-0657", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200806-11 (ibm-jdk-bin ibm-jre-bin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in IBM Java Development Kit (JDK)
and Java Runtime Environment (JRE), resulting in the execution of
arbitrary code.");
  script_tag(name:"solution", value:"All IBM JDK 1.5 users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/ibm-jdk-bin-1.5.0.7'

All IBM JDK 1.4 users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/ibm-jdk-bin-1.4.2.11'

All IBM JRE 1.5 users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/ibm-jre-bin-1.5.0.7'

All IBM JRE 1.4 users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-java/ibm-jre-bin-1.4.2.11'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200806-11");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=186277");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=198644");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=216112");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200804-20.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200806-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-java/ibm-jdk-bin", unaffected: make_list("ge 1.5.0.7", "rge 1.4.2.11"), vulnerable: make_list("lt 1.5.0.7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-java/ibm-jre-bin", unaffected: make_list("ge 1.5.0.7", "rge 1.4.2.11"), vulnerable: make_list("lt 1.5.0.7"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
