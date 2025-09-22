# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121014");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:25:42 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_name("Gentoo Security Advisory GLSA 201308-06");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in MySQL. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201308-06");
  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0117", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0486", "CVE-2012-0487", "CVE-2012-0488", "CVE-2012-0489", "CVE-2012-0490", "CVE-2012-0491", "CVE-2012-0492", "CVE-2012-0493", "CVE-2012-0494", "CVE-2012-0495", "CVE-2012-0496", "CVE-2012-0540", "CVE-2012-0553", "CVE-2012-0572", "CVE-2012-0574", "CVE-2012-0578", "CVE-2012-0583", "CVE-2012-1688", "CVE-2012-1689", "CVE-2012-1690", "CVE-2012-1696", "CVE-2012-1697", "CVE-2012-1702", "CVE-2012-1703", "CVE-2012-1705", "CVE-2012-1734", "CVE-2012-2102", "CVE-2012-2122", "CVE-2012-2749", "CVE-2012-3150", "CVE-2012-3158", "CVE-2012-3160", "CVE-2012-3163", "CVE-2012-3166", "CVE-2012-3167", "CVE-2012-3173", "CVE-2012-3177", "CVE-2012-3180", "CVE-2012-3197", "CVE-2012-5060", "CVE-2012-5096", "CVE-2012-5611", "CVE-2012-5612", "CVE-2012-5613", "CVE-2012-5614", "CVE-2012-5615", "CVE-2012-5627", "CVE-2013-0367", "CVE-2013-0368", "CVE-2013-0371", "CVE-2013-0375", "CVE-2013-0383", "CVE-2013-0384", "CVE-2013-0385", "CVE-2013-0386", "CVE-2013-0389", "CVE-2013-1492", "CVE-2013-1502", "CVE-2013-1506", "CVE-2013-1511", "CVE-2013-1512", "CVE-2013-1521", "CVE-2013-1523", "CVE-2013-1526", "CVE-2013-1531", "CVE-2013-1532", "CVE-2013-1544", "CVE-2013-1548", "CVE-2013-1552", "CVE-2013-1555", "CVE-2013-1566", "CVE-2013-1567", "CVE-2013-1570", "CVE-2013-1623", "CVE-2013-2375", "CVE-2013-2376", "CVE-2013-2378", "CVE-2013-2381", "CVE-2013-2389", "CVE-2013-2391", "CVE-2013-2392", "CVE-2013-2395", "CVE-2013-3802", "CVE-2013-3804", "CVE-2013-3808");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-19 16:22:00 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201308-06");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"dev-db/mysql", unaffected: make_list("ge 5.1.70"), vulnerable: make_list("lt 5.1.70"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
