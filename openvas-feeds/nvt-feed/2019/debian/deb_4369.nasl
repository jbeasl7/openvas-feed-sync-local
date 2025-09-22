# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704369");
  script_cve_id("CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-19967");
  script_tag(name:"creation_date", value:"2019-01-13 23:00:00 +0000 (Sun, 13 Jan 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-28 17:46:22 +0000 (Fri, 28 Dec 2018)");

  script_name("Debian: Security Advisory (DSA-4369-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4369-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4369-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4369");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-4369-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor:

CVE-2018-19961 / CVE-2018-19962 Paul Durrant discovered that incorrect TLB handling could result in denial of service, privilege escalation or information leaks.

CVE-2018-19965

Matthew Daley discovered that incorrect handling of the INVPCID instruction could result in denial of service by PV guests.

CVE-2018-19966

It was discovered that a regression in the fix to address CVE-2017-15595 could result in denial of service, privilege escalation or information leaks by a PV guest.

CVE-2018-19967

It was discovered that an error in some Intel CPUs could result in denial of service by a guest instance.

For the stable distribution (stretch), these problems have been fixed in version 4.8.5+shim4.10.2+xsa282-1+deb9u11.

We recommend that you upgrade your xen packages.

For the detailed security status of xen please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxen-4.8", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-amd64", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-arm64", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.8-armhf", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.8", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.8.5+shim4.10.2+xsa282-1+deb9u11", rls:"DEB9"))) {
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
