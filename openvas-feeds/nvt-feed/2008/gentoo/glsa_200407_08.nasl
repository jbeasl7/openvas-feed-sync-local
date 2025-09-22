# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54615");
  script_cve_id("CVE-2004-0633", "CVE-2004-0634", "CVE-2004-0635");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200407-08 (Ethereal)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities including one buffer overflow exist in Ethereal,
which may allow an attacker to run arbitrary code or crash the program.");
  script_tag(name:"solution", value:"All Ethereal users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '>=net-analyzer/ethereal-0.10.5'
    # emerge '>=net-analyzer/ethereal-0.10.5'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200407-08");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=56423");
  script_xref(name:"URL", value:"http://www.ethereal.com/appnotes/enpa-sa-00015.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200407-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-analyzer/ethereal", unaffected: make_list("ge 0.10.5"), vulnerable: make_list("le 0.10.4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
