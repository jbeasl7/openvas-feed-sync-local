# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60219");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-4324", "CVE-2007-4768", "CVE-2007-5275", "CVE-2007-6242", "CVE-2007-6243", "CVE-2007-6244", "CVE-2007-6245", "CVE-2007-6246");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200801-07 (netscape-flash)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been identified, the worst of which allow
arbitrary code execution on a user's system via a malicious Flash file.");
  script_tag(name:"solution", value:"All Adobe Flash Player users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-www/netscape-flash-9.0.115.0'

Please be advised that unaffected packages of the Adobe Flash Player have
known problems when used from within the Konqueror and Opera browsers.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200801-07");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=193519");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200711-30.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200801-07.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/netscape-flash", unaffected: make_list("ge 9.0.115.0"), vulnerable: make_list("lt 9.0.115.0"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
