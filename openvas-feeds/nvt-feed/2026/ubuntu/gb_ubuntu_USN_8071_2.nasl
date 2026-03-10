# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8071.2");
  script_cve_id("CVE-2026-2781");
  script_tag(name:"creation_date", value:"2026-03-06 04:33:38 +0000 (Fri, 06 Mar 2026)");
  script_version("2026-03-06T15:49:04+0000");
  script_tag(name:"last_modification", value:"2026-03-06 15:49:04 +0000 (Fri, 06 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-25 15:48:12 +0000 (Wed, 25 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-8071-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8071-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8071-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss' package(s) announced via the USN-8071-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-8071-1 fixed a vulnerability in nss. This update provides the
corresponding fix for Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS,
and Ubuntu 20.04 LTS.

Original advisory details:

 It was discovered that NSS incorrectly handled memory when performing
 certain GHASH operations. A remote attacker could use this issue to cause
 NSS to crash, resulting in a denial of service, or possibly execute
 arbitrary code.");

  script_tag(name:"affected", value:"'nss' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:3.28.4-0ubuntu0.14.04.5+esm13", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:3.28.4-0ubuntu0.16.04.14+esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:3.35-2ubuntu2.16+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:3.98-0ubuntu0.20.04.2+esm1", rls:"UBUNTU20.04 LTS"))) {
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
