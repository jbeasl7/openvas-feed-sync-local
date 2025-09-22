# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7269.2");
  script_cve_id("CVE-2024-31068", "CVE-2024-36293", "CVE-2024-39279");
  script_tag(name:"creation_date", value:"2025-02-25 04:04:18 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7269-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7269-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7269-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode' package(s) announced via the USN-7269-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7269-1 fixed vulnerabilities in Intel Microcode. This update provides
the corresponding updates for Ubuntu 24.04 LTS.

Original advisory details:

 Ke Sun, Paul Grosen and Alyssa Milburn discovered that some Intel(r)
 Processors did not properly implement Finite State Machines (FSMs) in
 Hardware Logic. A local privileged attacker could use this issue to cause
 a denial of service. (CVE-2024-31068)

 It was discovered that some Intel(r) Processors with Intel(r) SGX did not
 properly restrict access to the EDECCSSA user leaf function. A local
 authenticated attacker could use this issue to cause a denial of
 service. (CVE-2024-36293)

 Ke Sun, Alyssa Milburn, Benoit Morgan, and Erik Bjorge discovered that the
 UEFI firmware for some Intel(r) processors did not properly restrict
 access. An authenticated local attacker could use this issue to cause a
 denial of service. (CVE-2024-39279)");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Ubuntu 24.04.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20250211.0ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
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
