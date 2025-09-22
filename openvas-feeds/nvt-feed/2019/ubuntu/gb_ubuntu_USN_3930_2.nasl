# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843959");
  script_cve_id("CVE-2018-19824", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-7308", "CVE-2019-8912", "CVE-2019-8956", "CVE-2019-8980", "CVE-2019-9003", "CVE-2019-9162", "CVE-2019-9213");
  script_tag(name:"creation_date", value:"2019-04-03 06:40:38 +0000 (Wed, 03 Apr 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:45 +0000 (Tue, 05 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-3930-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3930-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3930-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-hwe' package(s) announced via the USN-3930-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3930-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.10.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 18.10 for Ubuntu 18.04 LTS.

Mathias Payer and Hui Peng discovered a use-after-free vulnerability in the
Advanced Linux Sound Architecture (ALSA) subsystem. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2018-19824)

Shlomi Oberman, Yuli Shapiro, and Ran Menscher discovered an information
leak in the Bluetooth implementation of the Linux kernel. An attacker
within Bluetooth range could use this to expose sensitive information
(kernel memory). (CVE-2019-3459, CVE-2019-3460)

Jann Horn discovered that the KVM implementation in the Linux kernel
contained a use-after-free vulnerability. An attacker in a guest VM with
access to /dev/kvm could use this to cause a denial of service (guest VM
crash). (CVE-2019-6974)

Jim Mattson and Felix Wilhelm discovered a use-after-free vulnerability in
the KVM subsystem of the Linux kernel, when using nested virtual machines.
A local attacker in a guest VM could use this to cause a denial of service
(system crash) or possibly execute arbitrary code in the host system.
(CVE-2019-7221)

Felix Wilhelm discovered that an information leak vulnerability existed in
the KVM subsystem of the Linux kernel, when nested virtualization is used.
A local attacker could use this to expose sensitive information (host
system memory to a guest VM). (CVE-2019-7222)

Jann Horn discovered that the eBPF implementation in the Linux kernel was
insufficiently hardened against Spectre V1 attacks. A local attacker could
use this to expose sensitive information. (CVE-2019-7308)

It was discovered that a use-after-free vulnerability existed in the user-
space API for crypto (af_alg) implementation in the Linux kernel. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2019-8912)

Jakub Jirasek discovered a use-after-free vulnerability in the SCTP
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-8956)

It was discovered that the Linux kernel did not properly deallocate memory
when handling certain errors while reading files. A local attacker could
use this to cause a denial of service (excessive memory consumption).
(CVE-2019-8980)

It was discovered that a use-after-free vulnerability existed in the IPMI
implementation in the Linux kernel. A local attacker with access to the
IPMI character device files could use this to cause a denial of service
(system crash). (CVE-2019-9003)

Jann Horn discovered that the SNMP NAT implementation in the Linux kernel
performed insufficient ASN.1 length checks. An attacker could use this to
cause a denial of service (system crash) or possibly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure, linux-hwe' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-1014-azure", ver:"4.18.0-1014.14~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-17-generic", ver:"4.18.0-17.18~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-17-generic-lpae", ver:"4.18.0-17.18~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-17-lowlatency", ver:"4.18.0-17.18~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-17-snapdragon", ver:"4.18.0-17.18~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.18.0.1014.13", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"4.18.0.17.67", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-18.04", ver:"4.18.0.17.67", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"4.18.0.17.67", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"4.18.0.17.67", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"4.18.0.17.67", rls:"UBUNTU18.04 LTS"))) {
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
