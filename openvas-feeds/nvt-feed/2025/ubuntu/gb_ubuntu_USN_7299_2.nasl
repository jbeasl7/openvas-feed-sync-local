# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7299.2");
  script_cve_id("CVE-2025-26594", "CVE-2025-26595", "CVE-2025-26596", "CVE-2025-26597", "CVE-2025-26598", "CVE-2025-26599", "CVE-2025-26600", "CVE-2025-26601");
  script_tag(name:"creation_date", value:"2025-03-11 04:04:32 +0000 (Tue, 11 Mar 2025)");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 16:15:39 +0000 (Tue, 25 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-7299-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7299-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7299-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server, xorg-server-hwe-16.04, xorg-server-hwe-18.04' package(s) announced via the USN-7299-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7299-1 fixed several vulnerabilities in X.Org. This update provides
the corresponding update for Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.

Original advisory details:

 Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled
 certain memory operations. An attacker could use these issues to cause the
 X Server to crash, leading to a denial of service, or possibly execute
 arbitrary code.");

  script_tag(name:"affected", value:"'xorg-server, xorg-server-hwe-16.04, xorg-server-hwe-18.04' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.18.4-0ubuntu0.12+esm15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core-hwe-16.04", ver:"2:1.19.6-1ubuntu4.1~16.04.6+esm7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:1.18.4-0ubuntu0.12+esm15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland-hwe-16.04", ver:"2:1.19.6-1ubuntu4.1~16.04.6+esm7", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.19.6-1ubuntu4.15+esm10", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core-hwe-18.04", ver:"2:1.20.8-2ubuntu2.2~18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:1.19.6-1ubuntu4.15+esm10", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland-hwe-18.04", ver:"2:1.20.8-2ubuntu2.2~18.04.11+esm2", rls:"UBUNTU18.04 LTS"))) {
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
