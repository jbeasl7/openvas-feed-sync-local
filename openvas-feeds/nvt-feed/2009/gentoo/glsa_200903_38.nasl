# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63693");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_cve_id("CVE-2007-6239", "CVE-2008-1612", "CVE-2009-0478");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Gentoo Security Advisory GLSA 200903-38 (Squid)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in Squid which allow for remote
Denial of Service attacks.");
  script_tag(name:"solution", value:"All Squid users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-proxy/squid-2.7.6'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200903-38");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=216319");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=257585");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200801-05.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200903-38.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-proxy/squid", unaffected: make_list("ge 2.7.6"), vulnerable: make_list("lt 2.7.6"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
