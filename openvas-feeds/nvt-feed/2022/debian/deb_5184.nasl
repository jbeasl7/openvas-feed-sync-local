# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705184");
  script_cve_id("CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166", "CVE-2022-23825", "CVE-2022-26362", "CVE-2022-26363", "CVE-2022-26364", "CVE-2022-29900");
  script_tag(name:"creation_date", value:"2022-07-17 01:00:16 +0000 (Sun, 17 Jul 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-21 15:26:49 +0000 (Tue, 21 Jun 2022)");

  script_name("Debian: Security Advisory (DSA-5184-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5184-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5184-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5184");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-404.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-407.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-5184-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor, which could result in privilege escalation. In addition this updates provides mitigations for the Retbleed speculative execution attack and the MMIO stale data vulnerabilities.

For additional information please refer to the following pages: [link moved to references] [link moved to references]

For the stable distribution (bullseye), these problems have been fixed in version 4.14.5+24-g87d90d511c-1.

We recommend that you upgrade your xen packages.

For the detailed security status of xen please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxencall1", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxendevicemodel1", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenevtchn1", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenforeignmemory1", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxengnttab1", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenhypfs1", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenmisc4.14", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxentoolcore1", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxentoollog1", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-doc", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.14-amd64", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.14-arm64", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.14-armhf", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-common", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.14", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.14.5+24-g87d90d511c-1", rls:"DEB11"))) {
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
