# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704469");
  script_cve_id("CVE-2019-10161", "CVE-2019-10167");
  script_tag(name:"creation_date", value:"2019-06-24 02:00:21 +0000 (Mon, 24 Jun 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-12 12:49:38 +0000 (Mon, 12 Aug 2019)");

  script_name("Debian: Security Advisory (DSA-4469-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4469-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4469-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4469");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libvirt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvirt' package(s) announced via the DSA-4469-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Libvirt, a virtualisation abstraction library, allowing an API client with read-only permissions to execute arbitrary commands via the virConnectGetDomainCapabilities API, or read or execute arbitrary files via the virDomainSaveImageGetXMLDesc API.

Additionally the libvirt's cpu map was updated to make addressing CVE-2018-3639, CVE-2017-5753, CVE-2017-5715, CVE-2018-12126, CVE-2018-12127, CVE-2018-12130 and CVE-2019-11091 easier by supporting the md-clear, ssbd, spec-ctrl and ibpb CPU features when picking CPU models without having to fall back to host-passthrough.

For the stable distribution (stretch), these problems have been fixed in version 3.0.0-4+deb9u4.

We recommend that you upgrade your libvirt packages.

For the detailed security status of libvirt please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libvirt' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnss-libvirt", ver:"3.0.0-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-clients", ver:"3.0.0-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon", ver:"3.0.0-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-daemon-system", ver:"3.0.0-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-dev", ver:"3.0.0-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-doc", ver:"3.0.0-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt-sanlock", ver:"3.0.0-4+deb9u4", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvirt0", ver:"3.0.0-4+deb9u4", rls:"DEB9"))) {
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
