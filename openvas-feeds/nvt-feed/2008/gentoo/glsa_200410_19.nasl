# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54710");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0968");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Gentoo Security Advisory GLSA 200410-19 (glibc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"The catchsegv script in the glibc package is vulnerable to symlink attacks,
potentially allowing a local user to overwrite arbitrary files with the
rights of the user running the script.");
  script_tag(name:"solution", value:"All glibc users should upgrade to the latest version:

    # emerge sync

    # emerge -pv sys-libs/glibc
    # emerge sys-libs/glibc");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200410-19");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11286");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=66358");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200410-19.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"sys-libs/glibc", unaffected: make_list("rge 2.2.5-r9", "rge 2.3.2-r12", "rge 2.3.3.20040420-r2", "rge 2.3.4.20040619-r2", "ge 2.3.4.20040808-r1"), vulnerable: make_list("le 2.3.4.20040808"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
