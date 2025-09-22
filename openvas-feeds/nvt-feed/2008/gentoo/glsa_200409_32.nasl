# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54688");
  script_cve_id("CVE-2004-0880", "CVE-2004-0881");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200409-32 (getmail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"getmail contains a vulnerability that could potentially allow any local
user to create or overwrite files in any directory on the system. This
flaw can be escalated further and possibly lead to a complete system
compromise.");
  script_tag(name:"solution", value:"All getmail users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=net-mail/getmail-4.2.0'
    # emerge '>=net-mail/getmail-4.2.0'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-32");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=64643");
  script_xref(name:"URL", value:"http://www.qcc.ca/~charlesc/software/getmail-4/CHANGELOG");
  script_xref(name:"URL", value:"http://article.gmane.org/gmane.mail.getmail.user/1430");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200409-32.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-mail/getmail", unaffected: make_list("ge 4.2.0"), vulnerable: make_list("lt 4.2.0"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
