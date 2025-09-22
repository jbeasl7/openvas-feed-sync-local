# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55198");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-2498");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200508-21 (phpwebsite)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"phpWebSite is vulnerable to multiple issues which result in the execution
of arbitrary code and SQL injection.");
  script_tag(name:"solution", value:"All phpWebSite users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/phpwebsite-0.10.2_rc2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200508-21");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14560");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=102785");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0497.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200508-21.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-apps/phpwebsite", unaffected: make_list("ge 0.10.2_rc2"), vulnerable: make_list("lt 0.10.2_rc2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
