# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66333");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-03 22:10:42 +0100 (Thu, 03 Dec 2009)");
  script_cve_id("CVE-2008-5005", "CVE-2008-5006", "CVE-2008-5514");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200911-03 (c-client uw-imap)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in the UW IMAP toolkit and the
    c-client library, the worst of which leading to the execution of
arbitrary
    code.");
  script_tag(name:"solution", value:"All c-client library users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/c-client-2007e'

All UW IMAP toolkit users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/uw-imap-2007e'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200911-03");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=245425");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=252567");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200911-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-libs/c-client", unaffected: make_list("ge 2007e"), vulnerable: make_list("lt 2007e"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-mail/uw-imap", unaffected: make_list("ge 2007e"), vulnerable: make_list("lt 2007e"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
