# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843041");
  script_cve_id("CVE-2016-10147", "CVE-2016-10150", "CVE-2016-8399", "CVE-2016-8632", "CVE-2016-9777");
  script_tag(name:"creation_date", value:"2017-02-04 04:46:31 +0000 (Sat, 04 Feb 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-09 17:06:11 +0000 (Thu, 09 Feb 2017)");

  script_name("Ubuntu: Security Advisory (USN-3190-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.10");

  script_xref(name:"Advisory-ID", value:"USN-3190-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3190-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-3190-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mikulas Patocka discovered that the asynchronous multibuffer cryptographic
daemon (mcryptd) in the Linux kernel did not properly handle being invoked
with incompatible algorithms. A local attacker could use this to cause a
denial of service (system crash). (CVE-2016-10147)

It was discovered that a use-after-free existed in the KVM subsystem of
the Linux kernel when creating devices. A local attacker could use this to
cause a denial of service (system crash). (CVE-2016-10150)

Qidan He discovered that the ICMP implementation in the Linux kernel did
not properly check the size of an ICMP header. A local attacker with
CAP_NET_ADMIN could use this to expose sensitive information.
(CVE-2016-8399)

Qian Zhang discovered a heap-based buffer overflow in the tipc_msg_build()
function in the Linux kernel. A local attacker could use to cause a denial
of service (system crash) or possibly execute arbitrary code with
administrative privileges. (CVE-2016-8632)

Dmitry Vyukov discovered that the KVM implementation in the Linux kernel
did not properly restrict the VCPU index when I/O APIC is enabled, An
attacker in a guest VM could use this to cause a denial of service (system
crash) or possibly gain privileges in the host OS. (CVE-2016-9777)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 16.10.");

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

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-37-generic", ver:"4.8.0-37.39", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-37-generic-lpae", ver:"4.8.0-37.39", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-37-lowlatency", ver:"4.8.0-37.39", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-37-powerpc-e500mc", ver:"4.8.0-37.39", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-37-powerpc-smp", ver:"4.8.0-37.39", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.8.0-37-powerpc64-emb", ver:"4.8.0-37.39", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.8.0.37.46", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.8.0.37.46", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.8.0.37.46", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"4.8.0.37.46", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"4.8.0.37.46", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"4.8.0.37.46", rls:"UBUNTU16.10"))) {
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
