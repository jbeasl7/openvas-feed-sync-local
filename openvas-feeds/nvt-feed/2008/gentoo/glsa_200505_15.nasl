# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54947");
  script_cve_id("CVE-2005-1704", "CVE-2005-1705");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200505-15 (gdb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the GNU debugger,
potentially allowing the execution of arbitrary code.");
  script_tag(name:"solution", value:"All gdb users should upgrade to the latest stable version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-devel/gdb-6.3-r3'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200505-15");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=88398");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=91398");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=91654");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200505-15.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"sys-devel/gdb", unaffected: make_list("ge 6.3-r3"), vulnerable: make_list("lt 6.3-r3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
