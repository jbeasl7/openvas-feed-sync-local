# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58650");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-1883", "CVE-2007-1887", "CVE-2007-1900", "CVE-2007-2756", "CVE-2007-2872", "CVE-2007-3007", "CVE-2007-3378", "CVE-2007-3806", "CVE-2007-3996", "CVE-2007-3997", "CVE-2007-3998", "CVE-2007-4652", "CVE-2007-4657", "CVE-2007-4658", "CVE-2007-4659", "CVE-2007-4660", "CVE-2007-4661", "CVE-2007-4662", "CVE-2007-4663", "CVE-2007-4670", "CVE-2007-4727", "CVE-2007-4782", "CVE-2007-4783", "CVE-2007-4784", "CVE-2007-4825", "CVE-2007-4840", "CVE-2007-4887");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Gentoo Security Advisory GLSA 200710-02 (php)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"PHP contains several vulnerabilities including buffer and integer overflows
which could lead to the remote execution of arbitrary code.");
  script_tag(name:"solution", value:"All PHP users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-lang/php-5.2.4_p20070914-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200710-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=179158");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=180556");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=191034");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200705-19.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200710-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-lang/php", unaffected: make_list("ge 5.2.4_p20070914-r2"), vulnerable: make_list("lt 5.2.4_p20070914-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
