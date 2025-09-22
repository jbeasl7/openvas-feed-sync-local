# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54533");
  script_cve_id("CVE-2004-0376");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200403-08 (oftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A remotely-exploitable overflow exists in oftpd, allowing an attacker to
crash the oftpd daemon.");
  script_tag(name:"solution", value:"All users should upgrade to the current version of the affected package:

    # emerge sync

    # emerge -pv '>=net-ftp/oftpd-0.3.7'
    # emerge '>=net-ftp/oftpd-0.3.7'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200403-08");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=45738");
  script_xref(name:"URL", value:"http://www.time-travellers.org/oftpd/oftpd-dos.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200403-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-ftp/oftpd", unaffected: make_list("ge 0.3.7"), vulnerable: make_list("le 0.3.6"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
