# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71177");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1674", "CVE-2010-1675", "CVE-2010-2948", "CVE-2010-2949", "CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326", "CVE-2011-3327");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-03-12 11:35:34 -0400 (Mon, 12 Mar 2012)");
  script_name("Gentoo Security Advisory GLSA 201202-02 (Quagga)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in Quagga, the worst of which
    leading to remote execution of arbitrary code.");
  script_tag(name:"solution", value:"All Quagga users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-misc/quagga-0.99.20'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201202-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=334303");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=359903");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=384651");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201202-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"net-misc/quagga", unaffected: make_list("ge 0.99.20"), vulnerable: make_list("lt 0.99.20"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
