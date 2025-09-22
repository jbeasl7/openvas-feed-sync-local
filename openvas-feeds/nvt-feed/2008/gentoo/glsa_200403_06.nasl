# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54531");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0224");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200403-06 (Courier)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Remote buffer overflow vulnerabilities have been found in Courier-IMAP and
Courier MTA. These exploits may allow the execution of arbitrary code,
allowing unauthorized access to a vulnerable system.");
  script_tag(name:"solution", value:"All users should upgrade to current versions of the affected packages:

    # emerge sync

    # emerge -pv '>=net-mail/courier-imap-3.0.0'
    # emerge '>=net-mail/courier-imap-3.0.0'

    # ** Or, depending on your installation... **

    # emerge -pv '>=net-mail/courier-0.45'
    # emerge '>=net-mail/courier-0.45'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200403-06");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=45584");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9845");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200403-06.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-mail/courier-imap", unaffected: make_list("ge 3.0.0"), vulnerable: make_list("lt 3.0.0"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-mail/courier", unaffected: make_list("ge 0.45"), vulnerable: make_list("lt 0.45"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
