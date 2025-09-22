# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70776");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-0015", "CVE-2011-0016", "CVE-2011-0427", "CVE-2011-0490", "CVE-2011-0491", "CVE-2011-0492", "CVE-2011-0493", "CVE-2011-1924");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:39 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201110-13 (Tor)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in Tor, the most severe of
    which may allow a remote attacker to execute arbitrary code.");
  script_tag(name:"solution", value:"All Tor users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/tor-0.2.1.30'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since April 2, 2011. It is likely that your system is
already
      no longer affected by this issue.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-13");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=351920");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=359789");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201110-13.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"net-misc/tor", unaffected: make_list("ge 0.2.1.30"), vulnerable: make_list("lt 0.2.1.30"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
