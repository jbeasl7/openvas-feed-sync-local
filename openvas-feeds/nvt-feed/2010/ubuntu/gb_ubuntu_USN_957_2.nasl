# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840471");
  script_cve_id("CVE-2010-2755");
  script_tag(name:"creation_date", value:"2010-07-30 13:25:34 +0000 (Fri, 30 Jul 2010)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-957-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-957-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-957-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-3.0, xulrunner-1.9.2' package(s) announced via the USN-957-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-957-1 fixed vulnerabilities in Firefox and Xulrunner. Daniel Holbert
discovered that the fix for CVE-2010-1214 introduced a regression which did
not properly initialize a plugin pointer. If a user were tricked into
viewing a malicious site, a remote attacker could use this to crash the
browser or run arbitrary code as the user invoking the program.
(CVE-2010-2755)

This update fixes the problem.

Original advisory details:

 Several flaws were discovered in the browser engine of Firefox. If a user
 were tricked into viewing a malicious site, a remote attacker could use
 this to crash the browser or possibly run arbitrary code as the user
 invoking the program. (CVE-2010-1208, CVE-2010-1209, CVE-2010-1211,
 CVE-2010-1212)

 An integer overflow was discovered in how Firefox processed plugin
 parameters. An attacker could exploit this to crash the browser or possibly
 run arbitrary code as the user invoking the program. (CVE-2010-1214)

 A flaw was discovered in the Firefox JavaScript engine. If a user were
 tricked into viewing a malicious site, a remote attacker code execute
 arbitrary JavaScript with chrome privileges. (CVE-2010-1215)

 An integer overflow was discovered in how Firefox processed CSS values. An
 attacker could exploit this to crash the browser or possibly run arbitrary
 code as the user invoking the program. (CVE-2010-2752)

 An integer overflow was discovered in how Firefox interpreted the XUL
 <tree> element. If a user were tricked into viewing a malicious site, a
 remote attacker could use this to crash the browser or possibly run
 arbitrary code as the user invoking the program. (CVE-2010-2753)

 Aki Helin discovered that libpng did not properly handle certain malformed
 PNG images. If a user were tricked into opening a crafted PNG file, an
 attacker could cause a denial of service or possibly execute arbitrary code
 with the privileges of the user invoking the program. (CVE-2010-1205)

 Yosuke Hasegawa and Vladimir Vukicevic discovered that the same-origin
 check in Firefox could be bypassed by utilizing the importScripts Web
 Worker method. If a user were tricked into viewing a malicious website, an
 attacker could exploit this to read data from other domains.
 (CVE-2010-1213, CVE-2010-1207)

 O. Andersen that Firefox did not properly map undefined positions within
 certain 8 bit encodings. An attacker could utilize this to perform
 cross-site scripting attacks. (CVE-2010-1210)

 Michal Zalewski discovered flaws in how Firefox processed the HTTP 204 (no
 content) code. An attacker could exploit this to spoof the location bar,
 such as in a phishing attack. (CVE-2010-1206)

 Jordi Chancel discovered that Firefox did not properly handle when a server
 responds to an HTTPS request with plaintext and then processes JavaScript
 history events. An attacker could exploit this to spoof the location bar,
 such as in a phishing attack. (CVE-2010-2751)

 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox, firefox-3.0, xulrunner-1.9.2' package(s) on Ubuntu 8.04, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"abrowser", ver:"3.6.8+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"3.6.8+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.8+build1+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox-3.0", ver:"3.6.8+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-1.9.2", ver:"1.9.2.8+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
