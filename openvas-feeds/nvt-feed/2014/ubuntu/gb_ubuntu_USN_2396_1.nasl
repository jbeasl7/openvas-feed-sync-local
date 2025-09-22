# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842022");
  script_cve_id("CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3646", "CVE-2014-3647");
  script_tag(name:"creation_date", value:"2014-11-11 05:22:35 +0000 (Tue, 11 Nov 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-11-10 15:03:25 +0000 (Mon, 10 Nov 2014)");

  script_name("Ubuntu: Security Advisory (USN-2396-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.10");

  script_xref(name:"Advisory-ID", value:"USN-2396-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2396-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2396-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nadav Amit reported that the KVM (Kernel Virtual Machine) mishandles
noncanonical addresses when emulating instructions that change the rip
(Instruction Pointer). A guest user with access to I/O or the MMIO can use
this flaw to cause a denial of service (system crash) of the guest.
(CVE-2014-3647)

A flaw was discovered with the handling of the invept instruction in the
KVM (Kernel Virtual Machine) subsystem of the Linux kernel. An unprivileged
guest user could exploit this flaw to cause a denial of service (system
crash) on the guest. (CVE-2014-3646)

Lars Bull reported a race condition in the PIT (programmable interrupt
timer) emulation in the KVM (Kernel Virtual Machine) subsystem of the Linux
kernel. A local guest user with access to PIT i/o ports could exploit this
flaw to cause a denial of service (crash) on the host. (CVE-2014-3611)

Lars Bull and Nadav Amit reported a flaw in how KVM (the Kernel Virtual
Machine) handles noncanonical writes to certain MSR registers. A privileged
guest user can exploit this flaw to cause a denial of service (kernel
panic) on the host. (CVE-2014-3610)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.10.");

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

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-24-generic", ver:"3.16.0-24.32", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-24-generic-lpae", ver:"3.16.0-24.32", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-24-lowlatency", ver:"3.16.0-24.32", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-24-powerpc-e500mc", ver:"3.16.0-24.32", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-24-powerpc-smp", ver:"3.16.0-24.32", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-24-powerpc64-emb", ver:"3.16.0-24.32", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-24-powerpc64-smp", ver:"3.16.0-24.32", rls:"UBUNTU14.10"))) {
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
