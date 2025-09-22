# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60087");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-4575");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200712-25 (openoffice openoffice-bin hsqldb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"An unspecified vulnerability has been reported in OpenOffice.org, possibly
allowing for the execution of arbitrary code.");
  script_tag(name:"solution", value:"All OpenOffice.org users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-2.3.1'

All OpenOffice.org binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-bin-2.3.1'

All HSQLDB users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-db/hsqldb-1.8.0.9'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200712-25");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=200771");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=201799");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200712-25.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 2.3.1"), vulnerable: make_list("lt 2.3.1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-bin", unaffected: make_list("ge 2.3.1"), vulnerable: make_list("lt 2.3.1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"dev-db/hsqldb", unaffected: make_list("ge 1.8.0.9"), vulnerable: make_list("lt 1.8.0.9"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
