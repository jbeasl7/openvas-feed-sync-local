# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121274");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:27:55 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_name("Gentoo Security Advisory GLSA 201410-01");
  script_tag(name:"insight", value:"Florian Weimer, Todd Sabin, Michal Zalewski et al. discovered further parsing flaws in Bash. The unaffected Gentoo packages listed in this GLSA contain the official patches to fix the issues tracked as CVE-2014-6277, CVE-2014-7186, and CVE-2014-7187. Furthermore, the official patch known as function prefix patch is included which prevents the exploitation of CVE-2014-6278.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201410-01");
  script_cve_id("CVE-2014-6277", "CVE-2014-7186", "CVE-2014-7187", "CVE-2014-6278");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201410-01");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"app-shells/bash", unaffected: make_list("ge 3.1_p22"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-shells/bash", unaffected: make_list("ge 3.2_p56"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-shells/bash", unaffected: make_list("ge 4.0_p43"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-shells/bash", unaffected: make_list("ge 4.1_p16"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-shells/bash", unaffected: make_list("ge 4.2_p52"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"app-shells/bash", unaffected: make_list(), vulnerable: make_list("lt 4.2_p52"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
