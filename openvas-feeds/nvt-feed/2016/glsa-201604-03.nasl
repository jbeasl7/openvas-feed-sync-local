# SPDX-FileCopyrightText: 2016 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121460");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"creation_date", value:"2016-04-06 14:30:00 +0300 (Wed, 06 Apr 2016)");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_name("Gentoo Security Advisory GLSA 201604-03");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Xen. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201604-03");
  script_cve_id("CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3497", "CVE-2012-3498", "CVE-2012-3515", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-6030", "CVE-2012-6031", "CVE-2012-6032", "CVE-2012-6033", "CVE-2012-6034", "CVE-2012-6035", "CVE-2012-6036", "CVE-2015-2151", "CVE-2015-3209", "CVE-2015-3259", "CVE-2015-3340", "CVE-2015-3456", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-4163", "CVE-2015-4164", "CVE-2015-5154", "CVE-2015-7311", "CVE-2015-7504", "CVE-2015-7812", "CVE-2015-7813", "CVE-2015-7814", "CVE-2015-7835", "CVE-2015-7871", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-7972", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8341", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8554", "CVE-2015-8555", "CVE-2016-2270", "CVE-2016-2271");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-13 12:15:00 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks");
  script_copyright("Copyright (C) 2016 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"app-emulation/xen", unaffected: make_list("ge 4.6.0-r9"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/xen", unaffected: make_list("ge 4.5.2-r5"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/xen", unaffected: make_list(), vulnerable: make_list("lt 4.6.0-r9"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/xen-pvgrub", unaffected: make_list(), vulnerable: make_list("lt 4.6.0"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/xen-tools", unaffected: make_list("ge 4.6.0-r9"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/xen-tools", unaffected: make_list("ge 4.5.2-r5"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/xen-tools", unaffected: make_list(), vulnerable: make_list("lt 4.6.0-r9"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/pvgrub", unaffected: make_list("ge 4.6.0"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/pvgrub", unaffected: make_list("ge 4.5.2"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-emulation/pvgrub", unaffected: make_list(), vulnerable: make_list("lt "))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
