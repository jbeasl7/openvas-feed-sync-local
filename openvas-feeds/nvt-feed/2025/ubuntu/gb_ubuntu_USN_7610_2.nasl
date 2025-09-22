# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7610.2");
  script_cve_id("CVE-2025-37798", "CVE-2025-37890", "CVE-2025-37932", "CVE-2025-37997", "CVE-2025-38000", "CVE-2025-38001");
  script_tag(name:"creation_date", value:"2025-07-10 08:14:31 +0000 (Thu, 10 Jul 2025)");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7610-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7610-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7610-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lowlatency, linux-oem-6.11' package(s) announced via the USN-7610-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Netfilter,
 - Network traffic control,
(CVE-2025-38001, CVE-2025-37997, CVE-2025-37798, CVE-2025-38000,
CVE-2025-37932, CVE-2025-37890)");

  script_tag(name:"affected", value:"'linux-lowlatency, linux-oem-6.11' package(s) on Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1025-oem", ver:"6.11.0-1025.25", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-24.04b", ver:"6.11.0-1025.25", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-6.11", ver:"6.11.0-1025.25", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1016-lowlatency", ver:"6.11.0-1016.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1016-lowlatency-64k", ver:"6.11.0-1016.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"6.11.0-1016.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-6.11", ver:"6.11.0-1016.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"6.11.0-1016.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-6.11", ver:"6.11.0-1016.17", rls:"UBUNTU24.10"))) {
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
