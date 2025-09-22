# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54680");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0801");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200409-24 (foomatic)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"The foomatic-rip filter in foomatic-filters contains a vulnerability which
may allow arbitrary command execution on the print server.");
  script_tag(name:"solution", value:"All foomatic users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=net-print/foomatic-3.0.2'
    # emerge '>=net-print/foomatic-3.0.2'

PLEASE NOTE: You should update foomatic, instead of foomatic-filters. This
will help to ensure that all other foomatic components remain functional.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-24");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=64166");
  script_xref(name:"URL", value:"http://www.linuxprinting.org/pipermail/foomatic-devel/2004q3/001996.html");
  script_xref(name:"URL", value:"http://www.mandrakesoft.com/security/advisories?name=MDKSA-2004:094");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200409-24.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-print/foomatic", unaffected: make_list("ge 3.0.2"), vulnerable: make_list("le 3.0.1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-print/foomatic-filters", unaffected: make_list("ge 3.0.2"), vulnerable: make_list("le 3.0.1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
