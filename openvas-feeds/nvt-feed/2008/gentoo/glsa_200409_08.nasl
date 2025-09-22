# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54665");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0755");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Gentoo Security Advisory GLSA 200409-08 (dev-lang/ruby)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"When used for CGI scripting, Ruby creates session files in /tmp with the
permissions of the default umask. Depending on that umask, local users may
be able to read sensitive data stored in session files.");
  script_tag(name:"solution", value:"All Ruby users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=dev-lang/ruby-your_version'
    # emerge '>=dev-lang/ruby-your_version'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-08");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=60525");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200409-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-lang/ruby", unaffected: make_list("rge 1.6.8-r11", "rge 1.8.0-r7", "ge 1.8.2_pre2"), vulnerable: make_list("lt 1.8.2_pre2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
