# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121250");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:27:42 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_name("Gentoo Security Advisory GLSA 201408-06");
  script_tag(name:"insight", value:"The png_push_read_chunk function in pngpread.c in the progressive decoder enters an infinite loop, when it encounters a zero-length IDAT chunk. In addition certain integer overflows have been detected and corrected.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201408-06");
  script_cve_id("CVE-2013-7353", "CVE-2013-7354", "CVE-2014-0333");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201408-06");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.6.10"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge &lt;1.3"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.5.18"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.5.19"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.5.20"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.5.21"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.5.22"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.5.23"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.5.24"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list("ge 1.5.25"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"media-libs/libpng", unaffected: make_list(), vulnerable: make_list("lt 1.6.10"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
