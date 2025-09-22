# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121231");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:27:28 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_name("Gentoo Security Advisory GLSA 201406-28");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Libav. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201406-28");
  script_cve_id("CVE-2012-2772", "CVE-2012-2775", "CVE-2012-2776", "CVE-2012-2777", "CVE-2012-2779", "CVE-2012-2783", "CVE-2012-2784", "CVE-2012-2786", "CVE-2012-2787", "CVE-2012-2788", "CVE-2012-2789", "CVE-2012-2790", "CVE-2012-2791", "CVE-2012-2793", "CVE-2012-2794", "CVE-2012-2796", "CVE-2012-2797", "CVE-2012-2798", "CVE-2012-2800", "CVE-2012-2801", "CVE-2012-2802", "CVE-2012-2803", "CVE-2012-2804", "CVE-2012-5144");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201406-28");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"media-video/libav", unaffected: make_list("ge 0.8.7"), vulnerable: make_list("lt 0.8.7"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
