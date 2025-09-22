# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892591");
  script_cve_id("CVE-2017-15041", "CVE-2018-16873", "CVE-2018-16874", "CVE-2019-16276", "CVE-2019-17596", "CVE-2019-9741", "CVE-2021-3114");
  script_tag(name:"creation_date", value:"2021-03-14 04:00:15 +0000 (Sun, 14 Mar 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-01 13:03:12 +0000 (Wed, 01 Nov 2017)");

  script_name("Debian: Security Advisory (DLA-2591-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2591-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2591-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/golang-1.7");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'golang-1.7' package(s) announced via the DLA-2591-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Go programming language. An attacker could trigger a denial-of-service (DoS), bypasss access control, and execute arbitrary code on the developer's computer.

CVE-2017-15041

Go allows go get remote command execution. Using custom domains, it is possible to arrange things so that example.com/pkg1 points to a Subversion repository but example.com/pkg1/pkg2 points to a Git repository. If the Subversion repository includes a Git checkout in its pkg2 directory and some other work is done to ensure the proper ordering of operations, go get can be tricked into reusing this Git checkout for the fetch of code from pkg2. If the Subversion repository's Git checkout has malicious commands in .git/hooks/, they will execute on the system running 'go get.'

CVE-2018-16873

The go get command is vulnerable to remote code execution when executed with the -u flag and the import path of a malicious Go package, as it may treat the parent directory as a Git repository root, containing malicious configuration.

CVE-2018-16874

The go get command is vulnerable to directory traversal when executed with the import path of a malicious Go package which contains curly braces (both '{' and '}' characters). The attacker can cause an arbitrary filesystem write, which can lead to code execution.

CVE-2019-9741

In net/http, CRLF injection is possible if the attacker controls a url parameter, as demonstrated by the second argument to http.NewRequest with rn followed by an HTTP header or a Redis command.

CVE-2019-16276

Go allows HTTP Request Smuggling.

CVE-2019-17596

Go can panic upon an attempt to process network traffic containing an invalid DSA public key. There are several attack scenarios, such as traffic from a client to a server that verifies client certificates.

CVE-2021-3114

crypto/elliptic/p224.go can generate incorrect outputs, related to an underflow of the lowest limb during the final complete reduction in the P-224 field.

For Debian 9 stretch, these problems have been fixed in version 1.7.4-2+deb9u3.

We recommend that you upgrade your golang-1.7 packages.

For the detailed security status of golang-1.7 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'golang-1.7' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.7", ver:"1.7.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.7-doc", ver:"1.7.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.7-go", ver:"1.7.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.7-src", ver:"1.7.4-2+deb9u3", rls:"DEB9"))) {
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
