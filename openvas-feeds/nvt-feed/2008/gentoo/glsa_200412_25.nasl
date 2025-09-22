# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54784");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-1125", "CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200412-25 (CUPS)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in CUPS, ranging from local Denial
of Service attacks to the remote execution of arbitrary code.");
  script_tag(name:"solution", value:"All CUPS users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-print/cups-1.1.23'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200412-25");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=74479");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=75197");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=77023");
  script_xref(name:"URL", value:"http://tigger.uic.edu/~jlongs2/holes/cups.txt");
  script_xref(name:"URL", value:"http://tigger.uic.edu/~jlongs2/holes/cups2.txt");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200412-25.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-print/cups", unaffected: make_list("ge 1.1.23"), vulnerable: make_list("lt 1.1.23"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
