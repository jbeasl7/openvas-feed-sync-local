# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54625");
  script_version("2023-07-19T05:05:15+0000");
  script_cve_id("CVE-2004-0700");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200407-18 (mod_ssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");

  script_tag(name:"insight", value:"A bug in mod_ssl may allow a remote attacker to execute arbitrary code when
  Apache is configured to use mod_ssl and mod_proxy.");

  script_tag(name:"solution", value:"All mod_ssl users should upgrade to the latest version:

  # emerge sync

  # emerge -pv '>=net-www/mod_ssl-2.8.19'

  # emerge '>=net-www/mod_ssl-2.8.19'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200407-18");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=57379");
  script_xref(name:"URL", value:"http://marc.info/?l=apache-modssl&m=109001100906749&w=2");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
  advisory GLSA 200407-18.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";

if ((res = ispkgvuln(pkg:"net-www/mod_ssl", unaffected: make_list("ge 2.8.19"), vulnerable: make_list("le 2.8.18"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
