# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6626.3");
  script_cve_id("CVE-2023-32250", "CVE-2023-32252", "CVE-2023-32257", "CVE-2023-34324", "CVE-2023-35827", "CVE-2023-46813", "CVE-2023-6039", "CVE-2023-6176", "CVE-2023-6622", "CVE-2024-0641");
  script_tag(name:"creation_date", value:"2024-02-19 04:08:59 +0000 (Mon, 19 Feb 2024)");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-02 13:54:18 +0000 (Wed, 02 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6626-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6626-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6626-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-5.15, linux-azure-fde, linux-azure-fde-5.15' package(s) announced via the USN-6626-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Quentin Minster discovered that a race condition existed in the KSMBD
implementation in the Linux kernel when handling sessions operations. A
remote attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-32250, CVE-2023-32252,
CVE-2023-32257)

Marek Marczykowski-Gorecki discovered that the Xen event channel
infrastructure implementation in the Linux kernel contained a race
condition. An attacker in a guest VM could possibly use this to cause a
denial of service (paravirtualized device unavailability). (CVE-2023-34324)

Zheng Wang discovered a use-after-free in the Renesas Ethernet AVB driver
in the Linux kernel during device removal. A privileged attacker could use
this to cause a denial of service (system crash). (CVE-2023-35827)

Tom Dohrmann discovered that the Secure Encrypted Virtualization (SEV)
implementation for AMD processors in the Linux kernel contained a race
condition when accessing MMIO registers. A local attacker in a SEV guest VM
could possibly use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2023-46813)

It was discovered that the Microchip USB Ethernet driver in the Linux
kernel contained a race condition during device removal, leading to a use-
after-free vulnerability. A physically proximate attacker could use this to
cause a denial of service (system crash). (CVE-2023-6039)

It was discovered that the TLS subsystem in the Linux kernel did not
properly perform cryptographic operations in some situations, leading to a
null pointer dereference vulnerability. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2023-6176)

Xingyuan Mo discovered that the netfilter subsystem in the Linux kernel did
not properly handle dynset expressions passed from userspace, leading to a
null pointer dereference vulnerability. A local attacker could use this to
cause a denial of service (system crash). (CVE-2023-6622)

It was discovered that the TIPC protocol implementation in the Linux kernel
did not properly handle locking during tipc_crypto_key_revoke() operations.
A local attacker could use this to cause a denial of service (kernel
deadlock). (CVE-2024-0641)");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-5.15, linux-azure-fde, linux-azure-fde-5.15' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1056-azure", ver:"5.15.0-1056.64~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1056-azure-fde", ver:"5.15.0-1056.64~20.04.1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.15.0.1056.64~20.04.45", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-cvm", ver:"5.15.0.1056.64~20.04.45", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"5.15.0.1056.64~20.04.1.34", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1056-azure", ver:"5.15.0-1056.64", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1056-azure-fde", ver:"5.15.0-1056.64.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde-lts-22.04", ver:"5.15.0.1056.64.34", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-22.04", ver:"5.15.0.1056.52", rls:"UBUNTU22.04 LTS"))) {
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
