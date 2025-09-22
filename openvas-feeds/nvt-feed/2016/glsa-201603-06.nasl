# SPDX-FileCopyrightText: 2016 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121448");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"creation_date", value:"2016-03-14 15:52:42 +0200 (Mon, 14 Mar 2016)");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_name("Gentoo Security Advisory GLSA 201603-06");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in FFmpeg. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201603-06");
  script_cve_id("CVE-2013-0860", "CVE-2013-0861", "CVE-2013-0862", "CVE-2013-0863", "CVE-2013-0864", "CVE-2013-0865", "CVE-2013-0866", "CVE-2013-0867", "CVE-2013-0868", "CVE-2013-0872", "CVE-2013-0873", "CVE-2013-0874", "CVE-2013-0875", "CVE-2013-0876", "CVE-2013-0877", "CVE-2013-0878", "CVE-2013-4263", "CVE-2013-4264", "CVE-2013-4265", "CVE-2013-7008", "CVE-2013-7009", "CVE-2013-7010", "CVE-2013-7011", "CVE-2013-7012", "CVE-2013-7013", "CVE-2013-7014", "CVE-2013-7015", "CVE-2013-7016", "CVE-2013-7017", "CVE-2013-7018", "CVE-2013-7019", "CVE-2013-7020", "CVE-2013-7021", "CVE-2013-7022", "CVE-2013-7023", "CVE-2013-7024", "CVE-2014-2097", "CVE-2014-2098", "CVE-2014-2263", "CVE-2014-5271", "CVE-2014-5272", "CVE-2014-7937", "CVE-2014-8541", "CVE-2014-8542", "CVE-2014-8543", "CVE-2014-8544", "CVE-2014-8545", "CVE-2014-8546", "CVE-2014-8547", "CVE-2014-8548", "CVE-2014-8549", "CVE-2014-9316", "CVE-2014-9317", "CVE-2014-9318", "CVE-2014-9319", "CVE-2014-9602", "CVE-2014-9603", "CVE-2014-9604", "CVE-2015-3395");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201603-06");
  script_copyright("Copyright (C) 2016 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"media-video/ffmpeg", unaffected: make_list("ge 2.6.3"), vulnerable: make_list("lt 2.6.3"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
