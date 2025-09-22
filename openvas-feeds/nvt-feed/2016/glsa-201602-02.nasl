# SPDX-FileCopyrightText: 2016 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121441");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"creation_date", value:"2016-02-18 07:28:03 +0200 (Thu, 18 Feb 2016)");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_name("Gentoo Security Advisory GLSA 201602-02");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the GNU C Library:");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201602-02");
  script_cve_id("CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8778", "CVE-2015-8779", "CVE-2013-7423", "CVE-2014-0475", "CVE-2014-5119", "CVE-2014-6040", "CVE-2014-7817", "CVE-2014-8121", "CVE-2014-9402", "CVE-2015-1472", "CVE-2015-1781");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-13 21:29:00 +0000 (Thu, 13 Jun 2019)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201602-02");
  script_copyright("Copyright (C) 2016 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"sys-libs/glibc", unaffected: make_list("ge 2.21-r2"), vulnerable: make_list("lt 2.21-r2"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
