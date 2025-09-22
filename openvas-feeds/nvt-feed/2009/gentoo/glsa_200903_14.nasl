# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63545");
  script_version("2024-02-14T05:07:39+0000");
  script_tag(name:"last_modification", value:"2024-02-14 05:07:39 +0000 (Wed, 14 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-03-13 19:24:56 +0100 (Fri, 13 Mar 2009)");
  script_cve_id("CVE-2009-0025", "CVE-2009-0265");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 17:43:48 +0000 (Tue, 13 Feb 2024)");
  script_name("Gentoo Security Advisory GLSA 200903-14 (bind)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Incomplete verification of RSA and DSA certificates might lead to spoofed
records authenticated using DNSSEC.");
  script_tag(name:"solution", value:"All BIND users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-dns/bind-9.4.3_p1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200903-14");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=254134");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=257949");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200903-14.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-dns/bind", unaffected: make_list("ge 9.4.3_p1"), vulnerable: make_list("lt 9.4.3_p1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
