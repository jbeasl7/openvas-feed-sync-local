# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8168.2");
  script_cve_id("CVE-2026-33056");
  script_tag(name:"creation_date", value:"2026-04-15 04:57:34 +0000 (Wed, 15 Apr 2026)");
  script_version("2026-04-15T06:17:01+0000");
  script_tag(name:"last_modification", value:"2026-04-15 06:17:01 +0000 (Wed, 15 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-24 16:17:11 +0000 (Tue, 24 Mar 2026)");

  script_name("Ubuntu: Security Advisory (USN-8168-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8168-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8168-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rustc, rustc-1.76, rustc-1.77, rustc-1.78, rustc-1.79, rustc-1.80' package(s) announced via the USN-8168-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-8168-1 fixed a vulnerability in Rust. This update provides the
corresponding update to Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04
LTS and Ubuntu 20.04 LTS.

Original advisory details:

 It was discovered that tar-rs embedded in rustc incorrectly handled
 symlinks when unpacking a tar archive. If a user or automated system were
 tricked into processing a specially crafted tar archive, a remote attacker
 could use this issue to modify permissions of arbitrary directories
 outside the extraction root, and possibly escalate privileges.");

  script_tag(name:"affected", value:"'rustc, rustc-1.76, rustc-1.77, rustc-1.78, rustc-1.79, rustc-1.80' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"rustc", ver:"1.31.0+dfsg1+llvm-2ubuntu1~14.04.1ubuntu1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"rustc", ver:"1.47.0+dfsg1+llvm-1ubuntu1~16.04.1ubuntu2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"rustc", ver:"1.65.0+dfsg0ubuntu1~llvm2-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"rustc", ver:"1.75.0+dfsg0ubuntu1~bpo0-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rustc-1.76", ver:"1.76.0+dfsg0ubuntu1~bpo0-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rustc-1.77", ver:"1.77.2+dfsg1ubuntu1~bpo0-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rustc-1.78", ver:"1.78.0+dfsg1ubuntu1~bpo0-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rustc-1.79", ver:"1.79.0+dfsg1ubuntu1~bpo0-0ubuntu0.20.04.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rustc-1.80", ver:"1.80.1+dfsg0ubuntu1~bpo0-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
