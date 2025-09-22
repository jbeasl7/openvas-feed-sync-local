# SPDX-FileCopyrightText: 2016 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121456");
  script_version("2024-07-17T05:05:38+0000");
  script_tag(name:"creation_date", value:"2016-03-14 15:52:48 +0200 (Mon, 14 Mar 2016)");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_name("Gentoo Security Advisory GLSA 201603-14");
  script_tag(name:"insight", value:"Various OpenJDK attack vectors in IcedTea, such as 2D, Corba, Hotspot, Libraries, and JAXP, exist which allows remote attackers to affect the confidentiality, integrity, and availability of vulnerable systems. This includes the possibility of remote execution of arbitrary code, information disclosure, or Denial of Service. Many of the vulnerabilities can only be exploited through sandboxed Java Web Start applications and java applets. Please reference the CVEs listed for specific details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201603-14");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0400", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0412", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4734", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4871", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:43:11 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201603-14");
  script_copyright("Copyright (C) 2016 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"dev-java/icedtea", unaffected: make_list("ge 7.2.6.4"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-java/icedtea", unaffected: make_list("ge 6.1.13.9"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-java/icedtea", unaffected: make_list(), vulnerable: make_list("lt 7.2.6.4"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-java/icedtea-bin", unaffected: make_list("ge 7.2.6.4"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-java/icedtea-bin", unaffected: make_list("ge 6.1.13.9"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-java/icedtea-bin", unaffected: make_list(), vulnerable: make_list("lt 7.2.6.4"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
