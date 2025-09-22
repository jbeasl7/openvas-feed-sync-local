# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121263");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:27:50 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_name("Gentoo Security Advisory GLSA 201408-19");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenOffice and Libreoffice. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201408-19");
  script_cve_id("CVE-2006-4339", "CVE-2009-0200", "CVE-2009-0201", "CVE-2009-0217", "CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302", "CVE-2010-0395", "CVE-2010-2935", "CVE-2010-2936", "CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-4253", "CVE-2010-4643", "CVE-2011-2713", "CVE-2012-0037", "CVE-2012-1149", "CVE-2012-2149", "CVE-2012-2334", "CVE-2012-2665", "CVE-2014-0247");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 03:22:33 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201408-19");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"app-office/openoffice-bin", unaffected: make_list("ge 3.5.5.3"), vulnerable: make_list("lt 3.5.5.3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-office/openoffice", unaffected: make_list(), vulnerable: make_list("lt 3.5.5.3"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-office/libreoffice", unaffected: make_list("ge 4.2.5.2"), vulnerable: make_list("lt 4.2.5.2"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-office/libreoffice-bin", unaffected: make_list("ge 4.2.5.2"), vulnerable: make_list("lt 4.2.5.2"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
