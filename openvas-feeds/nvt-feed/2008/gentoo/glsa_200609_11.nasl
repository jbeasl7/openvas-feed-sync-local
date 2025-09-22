# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57889");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2006-4095", "CVE-2006-4096");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 21:04:44 +0000 (Thu, 15 Feb 2024)");
  script_name("Gentoo Security Advisory GLSA 200609-11 (bind)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"ISC BIND contains two vulnerabilities allowing a Denial of Service under
certain conditions.");
  script_tag(name:"solution", value:"All BIND 9.3 users should update to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-dns/bind-9.3.2-r4'

All BIND 9.2 users should update to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-dns/bind-9.2.6-r4'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200609-11");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=146486");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200609-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-dns/bind", unaffected: make_list("ge 9.3.2-r4", "rge 9.2.6-r4"), vulnerable: make_list("lt 9.3.2-r4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
