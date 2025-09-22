# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54542");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2003-0989");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200404-03 (tcpdump)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"There are multiple vulnerabilities in tcpdump and libpcap related to
parsing of ISAKMP packets.");
  script_tag(name:"solution", value:"All tcpdump users should upgrade to the latest available version.
ADDITIONALLY, the net-libs/libpcap package should be upgraded.

    # emerge sync

    # emerge -pv '>=net-libs/libpcap-0.8.3-r1'
'>=net-analyzer/tcpdump-3.8.3-r1'
    # emerge '>=net-libs/libpcap-0.8.3-r1'
'>=net-analyzer/tcpdump-3.8.3-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200404-03");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=38206");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=46258");
  script_xref(name:"URL", value:"http://www.rapid7.com/advisories/R7-0017.html");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2004-008.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200404-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-analyzer/tcpdump", unaffected: make_list("ge 3.8.3-r1"), vulnerable: make_list("le 3.8.1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-libs/libpcap", unaffected: make_list("ge 0.8.3-r1"), vulnerable: make_list("le 0.8.1-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
