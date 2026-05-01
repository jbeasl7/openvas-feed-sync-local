# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8160.1");
  script_cve_id("CVE-2025-14847");
  script_tag(name:"creation_date", value:"2026-04-13 07:50:16 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-14T06:16:47+0000");
  script_tag(name:"last_modification", value:"2026-04-14 06:16:47 +0000 (Tue, 14 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8160-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8160-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8160-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mongodb' package(s) announced via the USN-8160-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that MongoDB incorrectly handled length parameters
in zlib-compressed network messages prior to authentication. An
unauthenticated remote attacker could possibly use this issue to
cause MongoDB to allocate an oversized memory buffer, resulting
in the exposure of sensitive information.");

  script_tag(name:"affected", value:"'mongodb' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mongodb", ver:"1:3.6.3-0ubuntu1.4+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mongodb-clients", ver:"1:3.6.3-0ubuntu1.4+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mongodb-server", ver:"1:3.6.3-0ubuntu1.4+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mongodb-server-core", ver:"1:3.6.3-0ubuntu1.4+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mongodb", ver:"1:3.6.9+really3.6.8+90~g8e540c0b6d-0ubuntu5.3+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mongodb-clients", ver:"1:3.6.9+really3.6.8+90~g8e540c0b6d-0ubuntu5.3+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mongodb-server", ver:"1:3.6.9+really3.6.8+90~g8e540c0b6d-0ubuntu5.3+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mongodb-server-core", ver:"1:3.6.9+really3.6.8+90~g8e540c0b6d-0ubuntu5.3+esm1", rls:"UBUNTU20.04 LTS"))) {
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
