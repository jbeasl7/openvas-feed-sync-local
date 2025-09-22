# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54566");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0421");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Gentoo Security Advisory GLSA 200405-06 (libpng)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A bug in the libpng library can be abused to crash programs making use of
that library to decode PNG images.");
  script_tag(name:"solution", value:"All users of libpng should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '>=media-libs/libpng-1.2.5-r5'
    # emerge '>=media-libs/libpng-1.2.5-r5'

You should also run revdep-rebuild to rebuild any packages that depend on
older versions of libpng :

    # revdep-rebuild");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200405-06");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10244");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=49887");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200405-06.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.2.5-r5"), vulnerable: make_list("le 1.2.5-r4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
