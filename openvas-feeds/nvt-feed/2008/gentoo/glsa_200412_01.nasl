# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54760");
  script_cve_id("CVE-2004-1161", "CVE-2004-1162");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200412-01 (scponly)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"rssh and scponly do not filter command-line options that can be exploited
to execute any command, thereby allowing a remote user to completely
bypass the restricted shell.");
  script_tag(name:"solution", value:"All scponly users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/scponly-4.0'

All rssh users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-shells/rssh/rssh-2.2.3'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200412-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=72815");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=72816");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/383046/2004-11-30/2004-12-06/0");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200412-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-misc/scponly", unaffected: make_list("ge 4.0"), vulnerable: make_list("lt 4.0"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-shells/rssh", unaffected: make_list("ge 2.2.3"), vulnerable: make_list("le 2.2.2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
