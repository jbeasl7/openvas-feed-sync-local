# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54564");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0179");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200405-04 (openoffice)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Several format string vulnerabilities are present in the Neon library
included in OpenOffice.org, allowing remote execution of arbitrary code
when connected to an untrusted WebDAV server.");
  script_tag(name:"solution", value:"There is no Ximian OpenOffice.org binary version including the fix yet. All
users of the openoffice-ximian-bin package making use of the WebDAV
openoffice-ximian source-based package should:

# emerge sync
# emerge -pv '>=app-office/openoffice-VERSION'
# emerge '>=app-office/openoffice-VERSION'

openoffice users on x86 should use version: 1.1.1-r1
openoffice users on sparc should use version: 1.1.0-r3
openoffice users on ppc should use version: 1.0.3-r1
openoffice-ximian users should use version: 1.1.51-r1
openoffice-bin users should use version: 1.1.2");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200405-04");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10136");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=47926");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200405-01.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200405-04.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 1.1.1-r1"), vulnerable: make_list("le 1.1.1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 1.0.3-r2"), vulnerable: make_list("le 1.0.3-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list("ge 1.1.0-r4"), vulnerable: make_list("le 1.1.0-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-ximian", unaffected: make_list("ge 1.1.51-r1"), vulnerable: make_list("le 1.1.51"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-bin", unaffected: make_list("ge 1.1.2"), vulnerable: make_list("lt 1.1.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-office/openoffice-ximian-bin", unaffected: make_list(), vulnerable: make_list("le 1.1.52"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
