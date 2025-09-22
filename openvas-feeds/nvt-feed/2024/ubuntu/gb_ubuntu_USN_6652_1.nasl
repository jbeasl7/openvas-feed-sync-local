# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6652.1");
  script_cve_id("CVE-2023-34324", "CVE-2023-35827", "CVE-2023-46813", "CVE-2023-46862", "CVE-2023-51780", "CVE-2023-51781", "CVE-2023-5972", "CVE-2023-6176", "CVE-2023-6531", "CVE-2023-6622", "CVE-2023-6915", "CVE-2024-0565", "CVE-2024-0582", "CVE-2024-0641", "CVE-2024-0646");
  script_tag(name:"creation_date", value:"2024-02-26 04:08:44 +0000 (Mon, 26 Feb 2024)");
  script_version("2024-02-26T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-02-26 05:06:11 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-24 21:04:26 +0000 (Wed, 24 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6652-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU23\.10");

  script_xref(name:"Advisory-ID", value:"USN-6652-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6652-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-6652-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marek Marczykowski-Gorecki discovered that the Xen event channel
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

It was discovered that the io_uring subsystem in the Linux kernel contained
a race condition, leading to a null pointer dereference vulnerability. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-46862)

It was discovered that a race condition existed in the ATM (Asynchronous
Transfer Mode) subsystem of the Linux kernel, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-51780)

It was discovered that a race condition existed in the AppleTalk networking
subsystem of the Linux kernel, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-51781)

It was discovered that the netfilter subsystem in the Linux kernel did not
properly validate inner tunnel netlink attributes, leading to a null
pointer dereference vulnerability. A local attacker could use this to cause
a denial of service (system crash). (CVE-2023-5972)

It was discovered that the TLS subsystem in the Linux kernel did not
properly perform cryptographic operations in some situations, leading to a
null pointer dereference vulnerability. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2023-6176)

Jann Horn discovered that a race condition existed in the Linux kernel when
handling io_uring over sockets, leading to a use-after-free vulnerability.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2023-6531)

Xingyuan Mo discovered that the netfilter subsystem in the Linux kernel did
not properly handle dynset expressions passed from userspace, leading to a
null pointer dereference vulnerability. A local attacker could use this to
cause a denial of service (system crash). (CVE-2023-6622)

Zhenghan Wang discovered that the generic ID allocator implementation in
the Linux kernel did not properly check for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 23.10.");

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

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1015-azure", ver:"6.5.0-1015.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.5.0-1015-azure-fde", ver:"6.5.0-1015.15", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.5.0.1015.17", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-fde", ver:"6.5.0.1015.17", rls:"UBUNTU23.10"))) {
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
