# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70806");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-2386", "CVE-2007-3744", "CVE-2007-3828", "CVE-2008-0989", "CVE-2008-2326", "CVE-2008-3630");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:42 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201201-05 (mDNSResponder)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in mDNSResponder, which
    could lead to execution of arbitrary code with root privileges.");
  script_tag(name:"solution", value:"All mDNSResponder users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/mDNSResponder-212.1'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since November 21, 2009. It is likely that your system is
      already no longer affected by this issue.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201201-05");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=290822");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201201-05.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"net-misc/mDNSResponder", unaffected: make_list("ge 212.1"), vulnerable: make_list("lt 212.1"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
