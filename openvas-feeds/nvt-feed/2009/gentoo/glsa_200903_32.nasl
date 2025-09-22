# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63616");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
  script_cve_id("CVE-2008-4096", "CVE-2008-4775", "CVE-2007-5977", "CVE-2006-6942", "CVE-2008-5621");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200903-32 (phpmyadmin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in phpMyAdmin, the worst of
which may allow for remote code execution.");
  script_tag(name:"solution", value:"All phpMyAdmin users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-db/phpmyadmin-2.11.9.4'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200903-32");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=237781");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=244914");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=246831");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=250752");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200903-32.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-db/phpmyadmin", unaffected: make_list("ge 2.11.9.4"), vulnerable: make_list("lt 2.11.9.4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
