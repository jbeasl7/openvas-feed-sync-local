# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704884");
  script_cve_id("CVE-2020-10730", "CVE-2020-27840", "CVE-2021-20277");
  script_tag(name:"creation_date", value:"2021-04-03 03:00:07 +0000 (Sat, 03 Apr 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-20 17:45:37 +0000 (Thu, 20 May 2021)");

  script_name("Debian: Security Advisory (DSA-4884-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4884-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4884-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4884");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ldb");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ldb' package(s) announced via the DSA-4884-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in ldb, a LDAP-like embedded database built on top of TDB.

CVE-2020-10730

Andrew Bartlett discovered a NULL pointer dereference and use-after-free flaw when handling ASQ and VLV LDAP controls and combinations with the LDAP paged_results feature.

CVE-2020-27840

Douglas Bagnall discovered a heap corruption flaw via crafted DN strings.

CVE-2021-20277

Douglas Bagnall discovered an out-of-bounds read vulnerability in handling LDAP attributes that contains multiple consecutive leading spaces.

For the stable distribution (buster), these problems have been fixed in version 2:1.5.1+really1.4.6-3+deb10u1.

We recommend that you upgrade your ldb packages.

For the detailed security status of ldb please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ldb' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ldb-tools", ver:"2:1.5.1+really1.4.6-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldb-dev", ver:"2:1.5.1+really1.4.6-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldb1", ver:"2:1.5.1+really1.4.6-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ldb", ver:"2:1.5.1+really1.4.6-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ldb-dev", ver:"2:1.5.1+really1.4.6-3+deb10u1", rls:"DEB10"))) {
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
