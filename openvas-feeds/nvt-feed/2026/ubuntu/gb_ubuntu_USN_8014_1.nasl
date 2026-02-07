# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8014.1");
  script_cve_id("CVE-2025-40019", "CVE-2025-40214");
  script_tag(name:"creation_date", value:"2026-02-06 04:34:56 +0000 (Fri, 06 Feb 2026)");
  script_version("2026-02-06T05:56:14+0000");
  script_tag(name:"last_modification", value:"2026-02-06 05:56:14 +0000 (Fri, 06 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8014-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8014-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8014-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-oem-6.17, linux-oracle, linux-raspi, linux-realtime' package(s) announced via the USN-8014-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Cryptographic API,
 - Unix domain sockets,
(CVE-2025-40019, CVE-2025-40214)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-oem-6.17, linux-oracle, linux-raspi, linux-realtime' package(s) on Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-1010-oem", ver:"6.17.0-1010.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-24.04d", ver:"6.17.0-1010.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-6.17", ver:"6.17.0-1010.10", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-1005-realtime", ver:"6.17.0-1005.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-1006-aws", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-1006-aws-64k", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-1006-gcp", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-1006-gcp-64k", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-1006-oracle", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-1006-oracle-64k", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-1007-azure", ver:"6.17.0-1007.7", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-1007-raspi", ver:"6.17.0-1007.7", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-12-generic", ver:"6.17.0-12.12", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.17.0-12-generic-64k", ver:"6.17.0-12.12", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-6.17", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k-6.17", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.17.0-1007.7", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-6.17", ver:"6.17.0-1007.7", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-6.17", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k-6.17", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.17.0-12.12", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-6.17", ver:"6.17.0-12.12", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.17.0-12.12", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-6.17", ver:"6.17.0-12.12", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-6.17", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k-6.17", ver:"6.17.0-1006.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.17.0-1007.7", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-6.17", ver:"6.17.0-1007.7", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-realtime", ver:"6.17.0-1005.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-realtime-6.17", ver:"6.17.0-1005.6", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.17.0-12.12", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-6.17", ver:"6.17.0-12.12", rls:"UBUNTU25.10"))) {
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
