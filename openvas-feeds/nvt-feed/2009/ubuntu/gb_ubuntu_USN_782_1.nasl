# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64324");
  script_cve_id("CVE-2009-1303", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1392", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841");
  script_tag(name:"creation_date", value:"2009-06-29 22:29:55 +0000 (Mon, 29 Jun 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-782-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-782-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-782-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-782-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws were discovered in the JavaScript engine of Thunderbird. If a
user had JavaScript enabled and were tricked into viewing malicious web
content, a remote attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2009-1303, CVE-2009-1305, CVE-2009-1392, CVE-2009-1833,
CVE-2009-1838)

Several flaws were discovered in the way Thunderbird processed malformed
URI schemes. If a user were tricked into viewing a malicious website and
had JavaScript and plugins enabled, a remote attacker could execute
arbitrary JavaScript or steal private data. (CVE-2009-1306, CVE-2009-1307,
CVE-2009-1309)

Cefn Hoile discovered Thunderbird did not adequately protect against
embedded third-party stylesheets. If JavaScript were enabled, an attacker
could exploit this to perform script injection attacks using XBL bindings.
(CVE-2009-1308)

Shuo Chen, Ziqing Mao, Yi-Min Wang, and Ming Zhang discovered that
Thunderbird did not properly handle error responses when connecting to a
proxy server. If a user had JavaScript enabled while using Thunderbird to
view websites and a remote attacker were able to perform a
machine-in-the-middle attack, this flaw could be exploited to view sensitive
information. (CVE-2009-1836)

It was discovered that Thunderbird could be made to run scripts with
elevated privileges. If a user had JavaScript enabled while having
certain non-default add-ons installed and were tricked into viewing a
malicious website, an attacker could cause a chrome privileged object, such
as the browser sidebar, to run arbitrary code via interactions with the
attacker controlled website. (CVE-2009-1841)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.8.10.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1", rls:"UBUNTU9.04"))) {
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
