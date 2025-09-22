# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7699.1");
  script_cve_id("CVE-2025-37947", "CVE-2025-37948", "CVE-2025-37949", "CVE-2025-37950", "CVE-2025-37951", "CVE-2025-37952", "CVE-2025-37954", "CVE-2025-37955", "CVE-2025-37956", "CVE-2025-37957", "CVE-2025-37958", "CVE-2025-37959", "CVE-2025-37960", "CVE-2025-37961", "CVE-2025-37962", "CVE-2025-37963", "CVE-2025-37964", "CVE-2025-37965", "CVE-2025-37966", "CVE-2025-37967", "CVE-2025-37968", "CVE-2025-37969", "CVE-2025-37970", "CVE-2025-37971", "CVE-2025-37972", "CVE-2025-37973", "CVE-2025-37992", "CVE-2025-37993", "CVE-2025-37994", "CVE-2025-37995", "CVE-2025-37996", "CVE-2025-37998", "CVE-2025-37999", "CVE-2025-38002", "CVE-2025-38005", "CVE-2025-38006", "CVE-2025-38007", "CVE-2025-38008", "CVE-2025-38009", "CVE-2025-38010", "CVE-2025-38011", "CVE-2025-38012", "CVE-2025-38013", "CVE-2025-38014", "CVE-2025-38015", "CVE-2025-38016", "CVE-2025-38018", "CVE-2025-38019", "CVE-2025-38020", "CVE-2025-38021", "CVE-2025-38022", "CVE-2025-38023", "CVE-2025-38024", "CVE-2025-38025", "CVE-2025-38027", "CVE-2025-38028", "CVE-2025-38056", "CVE-2025-38094", "CVE-2025-38095");
  script_tag(name:"creation_date", value:"2025-08-19 04:05:11 +0000 (Tue, 19 Aug 2025)");
  script_version("2025-08-19T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-08-19 05:39:49 +0000 (Tue, 19 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7699-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7699-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7699-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-6.14, linux-gcp, linux-gcp-6.14, linux-oracle, linux-oracle-6.14, linux-raspi, linux-realtime' package(s) announced via the USN-7699-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - ARM64 architecture,
 - RISC-V architecture,
 - x86 architecture,
 - Buffer Sharing and Synchronization framework,
 - DMA engine subsystem,
 - GPU drivers,
 - HID subsystem,
 - IIO ADC drivers,
 - IIO subsystem,
 - InfiniBand drivers,
 - Input Device core drivers,
 - Network drivers,
 - Mellanox network drivers,
 - PHY drivers,
 - Voltage and Current Regulator drivers,
 - VideoCore services drivers,
 - USB Type-C Connector System Software Interface driver,
 - Xen hypervisor drivers,
 - EROFS file system,
 - Network file system (NFS) client,
 - File systems infrastructure,
 - SMB network file system,
 - Network traffic control,
 - io_uring subsystem,
 - Kernel command line parsing driver,
 - Scheduler infrastructure,
 - Memory management,
 - Networking core,
 - MAC80211 subsystem,
 - Management Component Transport Protocol (MCTP),
 - Netfilter,
 - Open vSwitch,
 - TLS protocol,
 - Wireless networking,
 - SOF drivers,
(CVE-2025-38011, CVE-2025-38095, CVE-2025-37967, CVE-2025-38012,
CVE-2025-38019, CVE-2025-37960, CVE-2025-37973, CVE-2025-37958,
CVE-2025-38094, CVE-2025-37963, CVE-2025-37955, CVE-2025-38014,
CVE-2025-38025, CVE-2025-37970, CVE-2025-37947, CVE-2025-37966,
CVE-2025-37948, CVE-2025-38013, CVE-2025-37957, CVE-2025-38028,
CVE-2025-37962, CVE-2025-38002, CVE-2025-37996, CVE-2025-37992,
CVE-2025-37969, CVE-2025-38009, CVE-2025-38027, CVE-2025-38020,
CVE-2025-38023, CVE-2025-38008, CVE-2025-38015, CVE-2025-37954,
CVE-2025-38007, CVE-2025-38005, CVE-2025-37956, CVE-2025-37965,
CVE-2025-37972, CVE-2025-38006, CVE-2025-37971, CVE-2025-38056,
CVE-2025-37968, CVE-2025-38024, CVE-2025-37951, CVE-2025-38016,
CVE-2025-38022, CVE-2025-37964, CVE-2025-37994, CVE-2025-37952,
CVE-2025-37998, CVE-2025-37993, CVE-2025-38018, CVE-2025-38010,
CVE-2025-37995, CVE-2025-38021, CVE-2025-37999, CVE-2025-37961,
CVE-2025-37959, CVE-2025-37950, CVE-2025-37949)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-6.14, linux-gcp, linux-gcp-6.14, linux-oracle, linux-oracle-6.14, linux-raspi, linux-realtime' package(s) on Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1011-aws", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1011-aws-64k", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1011-oracle", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1011-oracle-64k", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1014-gcp", ver:"6.14.0-1014.15~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1014-gcp-64k", ver:"6.14.0-1014.15~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-6.14", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k-6.14", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.14.0-1014.15~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-6.14", ver:"6.14.0-1014.15~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k", ver:"6.14.0-1014.15~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k-6.14", ver:"6.14.0-1014.15~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-6.14", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k-6.14", ver:"6.14.0-1011.11~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1010-realtime", ver:"6.14.0-1010.10", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1011-aws", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1011-aws-64k", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1011-oracle", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1011-oracle-64k", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1012-raspi", ver:"6.14.0-1012.12", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1014-gcp", ver:"6.14.0-1014.15", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-1014-gcp-64k", ver:"6.14.0-1014.15", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-28-generic", ver:"6.14.0-28.28", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.14.0-28-generic-64k", ver:"6.14.0-28.28", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-6.14", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k-6.14", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.14.0-1014.15", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-6.14", ver:"6.14.0-1014.15", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k", ver:"6.14.0-1014.15", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k-6.14", ver:"6.14.0-1014.15", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.14.0-28.28", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-6.14", ver:"6.14.0-28.28", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.14.0-28.28", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-6.14", ver:"6.14.0-28.28", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-24.04", ver:"6.14.0-28.28", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-24.04a", ver:"6.14.0-28.28", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-6.14", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-64k-6.14", ver:"6.14.0-1011.11", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.14.0-1012.12", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-6.14", ver:"6.14.0-1012.12", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-realtime", ver:"6.14.0-1010.10", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-realtime-6.14", ver:"6.14.0-1010.10", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.14.0-28.28", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-6.14", ver:"6.14.0-28.28", rls:"UBUNTU25.04"))) {
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
