# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54798");
  script_cve_id("CVE-2004-1386");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200501-12 (tikiwiki)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A bug in TikiWiki allows certain users to upload and execute malicious PHP
scripts.");
  script_tag(name:"solution", value:"All TikiWiki users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/tikiwiki-1.8.4.1'

Note: Users with the vhosts USE flag set should manually use webapp-config
to finalize the update.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200501-12");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=75568");
  script_xref(name:"URL", value:"http://tikiwiki.org/tiki-read_article.php?articleId=97");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200501-12.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-apps/tikiwiki", unaffected: make_list("ge 1.8.4.1"), vulnerable: make_list("lt 1.8.4.1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
