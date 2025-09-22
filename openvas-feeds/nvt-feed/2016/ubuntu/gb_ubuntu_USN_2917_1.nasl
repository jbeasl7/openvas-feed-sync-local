# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842678");
  script_cve_id("CVE-2016-1950", "CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954", "CVE-2016-1955", "CVE-2016-1956", "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1959", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1963", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1967", "CVE-2016-1968", "CVE-2016-1973", "CVE-2016-1974", "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_tag(name:"creation_date", value:"2016-03-10 05:16:26 +0000 (Thu, 10 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-15 18:42:36 +0000 (Tue, 15 Mar 2016)");

  script_name("Ubuntu: Security Advisory (USN-2917-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2917-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2917-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2917-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Francis Gabriel discovered a buffer overflow during ASN.1 decoding in NSS.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2016-1950)

Bob Clary, Christoph Diehl, Christian Holler, Andrew McCreight, Daniel
Holbert, Jesse Ruderman, Randell Jesup, Carsten Book, Gian-Carlo Pascutto,
Tyson Smith, Andrea Marchesini, and Jukka Jylanki discovered multiple
memory safety issues in Firefox. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2016-1952,
CVE-2016-1953)

Nicolas Golubovic discovered that CSP violation reports can be used to
overwrite local files. If a user were tricked in to opening a specially
crafted website with addon signing disabled and unpacked addons installed,
an attacker could potentially exploit this to gain additional privileges.
(CVE-2016-1954)

Muneaki Nishimura discovered that CSP violation reports contained full
paths for cross-origin iframe navigations. An attacker could potentially
exploit this to steal confidential data. (CVE-2016-1955)

Ucha Gobejishvili discovered that performing certain WebGL operations
resulted in memory resource exhaustion with some Intel GPUs, requiring
a reboot. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service. (CVE-2016-1956)

Jose Martinez and Romina Santillan discovered a memory leak in
libstagefright during MPEG4 video file processing in some circumstances.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service via
memory exhaustion. (CVE-2016-1957)

Abdulrahman Alqabandi discovered that the addressbar could be blank or
filled with page defined content in some circumstances. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to conduct URL spoofing attacks. (CVE-2016-1958)

Looben Yang discovered an out-of-bounds read in Service Worker Manager. If
a user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2016-1959)

A use-after-free was discovered in the HTML5 string parser. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2016-1960)

A use-after-free ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"45.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"45.0+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"45.0+build2-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
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
