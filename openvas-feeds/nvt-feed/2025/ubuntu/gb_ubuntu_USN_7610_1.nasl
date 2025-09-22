# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7610.1");
  script_cve_id("CVE-2025-37798", "CVE-2025-37890", "CVE-2025-37932", "CVE-2025-37997", "CVE-2025-38000", "CVE-2025-38001");
  script_tag(name:"creation_date", value:"2025-07-03 04:12:00 +0000 (Thu, 03 Jul 2025)");
  script_version("2025-07-03T05:42:53+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:53 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7610-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7610-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7610-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-gcp-6.11, linux-hwe-6.11, linux-oracle, linux-raspi, linux-realtime' package(s) announced via the USN-7610-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Netfilter,
 - Network traffic control,
(CVE-2025-38001, CVE-2025-37997, CVE-2025-37798, CVE-2025-38000,
CVE-2025-37932, CVE-2025-37890)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-gcp-6.11, linux-hwe-6.11, linux-oracle, linux-raspi, linux-realtime' package(s) on Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1017-gcp", ver:"6.11.0-1017.17~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1017-gcp-64k", ver:"6.11.0-1017.17~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-29-generic", ver:"6.11.0-29.29~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-29-generic-64k", ver:"6.11.0-29.29~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.11.0-1017.17~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-6.11", ver:"6.11.0-1017.17~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k", ver:"6.11.0-1017.17~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k-6.11", ver:"6.11.0-1017.17~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-6.11", ver:"6.11.0-29.29~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-6.11", ver:"6.11.0-29.29~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-hwe-24.04", ver:"6.11.0-29.29~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-24.04", ver:"6.11.0-29.29~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-6.11", ver:"6.11.0-29.29~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-24.04", ver:"6.11.0-29.29~24.04.1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1012-realtime", ver:"6.11.0-1012.12", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1015-raspi", ver:"6.11.0-1015.15", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1016-aws", ver:"6.11.0-1016.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1017-gcp", ver:"6.11.0-1017.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1017-gcp-64k", ver:"6.11.0-1017.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1018-oracle", ver:"6.11.0-1018.19", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-1018-oracle-64k", ver:"6.11.0-1018.19", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-29-generic", ver:"6.11.0-29.29", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.11.0-29-generic-64k", ver:"6.11.0-29.29", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.11.0-1016.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-6.11", ver:"6.11.0-1016.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.11.0-1017.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-6.11", ver:"6.11.0-1017.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k", ver:"6.11.0-1017.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k-6.11", ver:"6.11.0-1017.17", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.11.0-29.29", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-6.11", ver:"6.11.0-29.29", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.11.0-29.29", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-6.11", ver:"6.11.0-29.29", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.11.0-1018.19", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-6.11", ver:"6.11.0-1018.19", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k", ver:"6.11.0-1018.19", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k-6.11", ver:"6.11.0-1018.19", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.11.0-1015.15", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-6.11", ver:"6.11.0-1015.15", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-realtime", ver:"6.11.0-1012.12", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-realtime-6.11", ver:"6.11.0-1012.12", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.11.0-29.29", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-6.11", ver:"6.11.0-29.29", rls:"UBUNTU24.10"))) {
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
