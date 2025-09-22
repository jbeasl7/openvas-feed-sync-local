# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61444");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2008-2266");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200808-11 (nzbget uudeview)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A vulnerability in UUDeview may allow local attackers to conduct symlink
attacks.");
  script_tag(name:"solution", value:"All UUDview users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/uudeview-0.5.20-r1'

All NZBget users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=news-nntp/nzbget-0.4.0'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200808-11");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=222275");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=224193");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200808-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-text/uudeview", unaffected: make_list("ge 0.5.20-r1"), vulnerable: make_list("lt 0.5.20-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"news-nntp/nzbget", unaffected: make_list("ge 0.4.0"), vulnerable: make_list("lt 0.4.0"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
