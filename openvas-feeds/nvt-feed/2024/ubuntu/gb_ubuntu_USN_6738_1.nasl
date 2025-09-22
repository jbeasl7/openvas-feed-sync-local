# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6738.1");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2024-04-24 04:09:36 +0000 (Wed, 24 Apr 2024)");
  script_version("2024-04-25T05:05:14+0000");
  script_tag(name:"last_modification", value:"2024-04-25 05:05:14 +0000 (Thu, 25 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("Ubuntu: Security Advisory (USN-6738-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6738-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6738-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lxd' package(s) announced via the USN-6738-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fabian Baumer, Marcus Brinkmann, and Jorg Schwenk discovered that LXD
incorrectly handled the handshake phase and the use of sequence numbers in SSH
Binary Packet Protocol (BPP). If a user or an automated system were tricked
into opening a specially crafted input file, a remote attacker could possibly
use this issue to bypass integrity checks.");

  script_tag(name:"affected", value:"'lxd' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-lxc-lxd-dev", ver:"2.0.11-0ubuntu1~16.04.4+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxc2", ver:"2.0.11-0ubuntu1~16.04.4+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd", ver:"2.0.11-0ubuntu1~16.04.4+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-client", ver:"2.0.11-0ubuntu1~16.04.4+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-tools", ver:"2.0.11-0ubuntu1~16.04.4+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"lxd", ver:"3.0.3-0ubuntu1~18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-client", ver:"3.0.3-0ubuntu1~18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-tools", ver:"3.0.3-0ubuntu1~18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
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
