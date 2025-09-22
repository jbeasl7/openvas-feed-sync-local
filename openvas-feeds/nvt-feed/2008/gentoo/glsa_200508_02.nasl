# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55007");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-2390");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_name("Gentoo Security Advisory GLSA 200508-02 (proftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Under specific circumstances, ProFTPD is vulnerable to format string
vulnerabilities, potentially resulting in the execution of arbitrary code.");
  script_tag(name:"solution", value:"All ProFTPD users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-ftp/proftpd-1.2.10-r7'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200508-02");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14380");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14381");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=100364");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200508-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-ftp/proftpd", unaffected: make_list("ge 1.2.10-r7"), vulnerable: make_list("lt 1.2.10-r7"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
