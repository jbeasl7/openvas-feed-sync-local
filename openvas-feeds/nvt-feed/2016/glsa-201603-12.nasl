# SPDX-FileCopyrightText: 2016 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121454");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"creation_date", value:"2016-03-14 15:52:48 +0200 (Mon, 14 Mar 2016)");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_name("Gentoo Security Advisory GLSA 201603-12");
  script_tag(name:"insight", value:"Multiple format string vulnerabilities in FlightGear and SimGear allow user-assisted remote attackers to cause a denial of service and possibly execute arbitrary code via format string specifiers in certain data chunk values in an aircraft xml model.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201603-12");
  script_cve_id("CVE-2012-2090", "CVE-2012-2091");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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

if((res=ispkgvuln(pkg:"games-simulation/flightgear", unaffected: make_list("ge 3.4.0"), vulnerable: make_list("lt 3.4.0"))) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"games-simulation/simgear", unaffected: make_list("ge 3.4.0"), vulnerable: make_list("lt 3.4.0"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
