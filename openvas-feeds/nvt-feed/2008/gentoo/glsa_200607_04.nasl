# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57120");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2006-2313", "CVE-2006-2314");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200607-04 (postgresql)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A flaw in the multibyte character handling allows execution of arbitrary
SQL statements.");
  script_tag(name:"solution", value:"All PostgreSQL users should upgrade to the latest version in the respective
branch they are using:

    # emerge --sync
    # emerge --ask --oneshot --verbose dev-db/postgresql

Note: While a fix exists for the 7.3 branch it doesn't currently work on
Gentoo. All 7.3.x users of PostgreSQL should consider updating their
installations to the 7.4 (or higher) branch as soon as possible!");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200607-04");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=134168");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/techdocs.50");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200607-04.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-db/postgresql", unaffected: make_list("ge 8.0.8", "rge 7.4.13"), vulnerable: make_list("lt 8.0.8"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
