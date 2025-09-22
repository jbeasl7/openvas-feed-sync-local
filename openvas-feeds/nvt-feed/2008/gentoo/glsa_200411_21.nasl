# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54742");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0930", "CVE-2004-0882");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200411-21 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Samba is vulnerable to a buffer overflow that could lead to execution of
arbitrary code (CVE-2004-0882). Another flaw in Samba may allow a remote
attacker to cause a Denial of Service by excessive consumption of CPU
cycles (CVE-2004-0930).");
  script_tag(name:"solution", value:"All Samba users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-fs/samba-3.0.8'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200411-21");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=70429");
  script_xref(name:"URL", value:"http://security.e-matters.de/advisories/132004.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200411-21.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-fs/samba", unaffected: make_list("ge 3.0.8", "lt 3.0"), vulnerable: make_list("lt 3.0.8"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
