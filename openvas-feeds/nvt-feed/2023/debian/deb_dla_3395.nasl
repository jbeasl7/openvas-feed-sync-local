# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3395");
  script_cve_id("CVE-2020-28367", "CVE-2021-33196", "CVE-2021-36221", "CVE-2021-38297", "CVE-2021-39293", "CVE-2021-41771", "CVE-2021-44716", "CVE-2021-44717", "CVE-2022-23806", "CVE-2022-24921");
  script_tag(name:"creation_date", value:"2023-04-21 04:24:27 +0000 (Fri, 21 Apr 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-21 16:31:04 +0000 (Thu, 21 Oct 2021)");

  script_name("Debian: Security Advisory (DLA-3395-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3395-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3395-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/golang-1.11");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'golang-1.11' package(s) announced via the DLA-3395-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the Go programming language. An attacker could trigger a denial-of-service (DoS), invalid cryptographic computation, information leak, or arbitrary code execution on the developer's computer in specific situations.

CVE-2020-28367

Code injection in the go command with cgo allows arbitrary code execution at build time via malicious gcc flags specified via a #cgo directive.

CVE-2021-33196

In archive/zip, a crafted file count (in an archive's header) can cause a NewReader or OpenReader panic.

CVE-2021-36221

Go has a race condition that can lead to a net/http/httputil ReverseProxy panic upon an ErrAbortHandler abort.

CVE-2021-38297

Go has a Buffer Overflow via large arguments in a function invocation from a WASM module, when GOARCH=wasm GOOS=js is used.

CVE-2021-39293

This issue exists because of an incomplete fix for CVE-2021-33196.

CVE-2021-41771

ImportedSymbols in debug/macho (for Open or OpenFat) Accesses a Memory Location After the End of a Buffer, aka an out-of-bounds slice situation.

CVE-2021-44716

net/http allows uncontrolled memory consumption in the header canonicalization cache via HTTP/2 requests.

CVE-2021-44717

Go on UNIX allows write operations to an unintended file or unintended network connection as a consequence of erroneous closing of file descriptor 0 after file-descriptor exhaustion.

CVE-2022-23806

Curve.IsOnCurve in crypto/elliptic can incorrectly return true in situations with a big.Int value that is not a valid field element.

CVE-2022-24921

regexp.Compile allows stack exhaustion via a deeply nested expression.

For Debian 10 buster, these problems have been fixed in version 1.11.6-1+deb10u6.

We recommend that you upgrade your golang-1.11 packages.

For the detailed security status of golang-1.11 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'golang-1.11' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.11", ver:"1.11.6-1+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.11-doc", ver:"1.11.6-1+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.11-go", ver:"1.11.6-1+deb10u6", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.11-src", ver:"1.11.6-1+deb10u6", rls:"DEB10"))) {
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
