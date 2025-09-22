# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843647");
  script_cve_id("CVE-2018-10853", "CVE-2018-14633", "CVE-2018-15572", "CVE-2018-15594", "CVE-2018-17182", "CVE-2018-6554", "CVE-2018-6555");
  script_tag(name:"creation_date", value:"2018-10-02 06:12:15 +0000 (Tue, 02 Oct 2018)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-14 20:31:44 +0000 (Wed, 14 Nov 2018)");

  script_name("Ubuntu: Security Advisory (USN-3777-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3777-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3777-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/Variant4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-kvm, linux-oem, linux-raspi2' package(s) announced via the USN-3777-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the vmacache subsystem did not properly handle
sequence number overflows, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or execute arbitrary code. (CVE-2018-17182)

It was discovered that the paravirtualization implementation in the Linux
kernel did not properly handle some indirect calls, reducing the
effectiveness of Spectre v2 mitigations for paravirtual guests. A local
attacker could use this to expose sensitive information. (CVE-2018-15594)

It was discovered that microprocessors utilizing speculative execution and
prediction of return addresses via Return Stack Buffer (RSB) may allow
unauthorized memory reads via sidechannel attacks. An attacker could use
this to expose sensitive information. (CVE-2018-15572)

Andy Lutomirski and Mika Penttila discovered that the KVM implementation
in the Linux kernel did not properly check privilege levels when emulating
some instructions. An unprivileged attacker in a guest VM could use this to
escalate privileges within the guest. (CVE-2018-10853)

It was discovered that a stack-based buffer overflow existed in the iSCSI
target implementation of the Linux kernel. A remote attacker could use this
to cause a denial of service (system crash). (CVE-2018-14633)

It was discovered that a memory leak existed in the IRDA subsystem of the
Linux kernel. A local attacker could use this to cause a denial of service
(kernel memory exhaustion). (CVE-2018-6554)

It was discovered that a use-after-free vulnerability existed in the IRDA
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-6555)

USN 3652-1 added a mitigation for Speculative Store Bypass
a.k.a. Spectre Variant 4 (CVE-2018-3639). This update provides the
corresponding mitigation for ARM64 processors. Please note that for
this mitigation to be effective, an updated firmware for the processor
may be required.");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-kvm, linux-oem, linux-raspi2' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1021-gcp", ver:"4.15.0-1021.22", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1021-oem", ver:"4.15.0-1021.24", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1023-aws", ver:"4.15.0-1023.23", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1023-kvm", ver:"4.15.0-1023.23", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1024-raspi2", ver:"4.15.0-1024.26", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-36-generic", ver:"4.15.0-36.39", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-36-generic-lpae", ver:"4.15.0-36.39", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-36-lowlatency", ver:"4.15.0-36.39", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-36-snapdragon", ver:"4.15.0-36.39", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.15.0.1023.23", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1021.23", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.15.0.36.38", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.15.0.36.38", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1021.23", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.15.0.1023.23", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.15.0.36.38", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.1021.23", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.15.0.1024.22", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.15.0.36.38", rls:"UBUNTU18.04 LTS"))) {
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
