# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892865");
  script_cve_id("CVE-2017-11521", "CVE-2018-12584");
  script_tag(name:"creation_date", value:"2021-12-30 02:00:10 +0000 (Thu, 30 Dec 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-17 17:01:32 +0000 (Mon, 17 Sep 2018)");

  script_name("Debian: Security Advisory (DLA-2865-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2865-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2865-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/resiprocate");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'resiprocate' package(s) announced via the DLA-2865-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were fixed in the reSIProcate SIP stack.

CVE-2017-11521

The SdpContents::Session::Medium::parse function allowed remote attackers to cause a denial of service.

CVE-2018-12584

The ConnectionBase::preparseNewBytes function allowed remote attackers to cause a denial of service or possibly execute arbitrary code when TLS communication is enabled.

For Debian 9 stretch, these problems have been fixed in version 1:1.11.0~beta1-3+deb9u2.

We recommend that you upgrade your resiprocate packages.

For the detailed security status of resiprocate please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'resiprocate' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"librecon-1.11", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librecon-1.11-dev", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libresiprocate-1.11", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libresiprocate-1.11-dev", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libresiprocate-turn-client-1.11", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libresiprocate-turn-client-1.11-dev", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"repro", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"resiprocate-turn-server", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"resiprocate-turn-server-psql", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sipdialer", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"telepathy-resiprocate", ver:"1:1.11.0~beta1-3+deb9u2", rls:"DEB9"))) {
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
