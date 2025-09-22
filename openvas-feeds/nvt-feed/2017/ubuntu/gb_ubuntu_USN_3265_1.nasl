# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843139");
  script_cve_id("CVE-2017-5669", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6347", "CVE-2017-6348", "CVE-2017-7374");
  script_tag(name:"creation_date", value:"2017-04-25 04:32:55 +0000 (Tue, 25 Apr 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-28 15:47:44 +0000 (Tue, 28 Mar 2017)");

  script_name("Ubuntu: Security Advisory (USN-3265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3265-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3265-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gke, linux-raspi2, linux-snapdragon' package(s) announced via the USN-3265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a use-after-free flaw existed in the filesystem
encryption subsystem in the Linux kernel. A local attacker could use this
to cause a denial of service (system crash). (CVE-2017-7374)

Andrey Konovalov discovered an out-of-bounds access in the IPv6 Generic
Routing Encapsulation (GRE) tunneling implementation in the Linux kernel.
An attacker could use this to possibly expose sensitive information.
(CVE-2017-5897)

Andrey Konovalov discovered that the IPv4 implementation in the Linux
kernel did not properly handle invalid IP options in some situations. An
attacker could use this to cause a denial of service or possibly execute
arbitrary code. (CVE-2017-5970)

Gareth Evans discovered that the shm IPC subsystem in the Linux kernel did
not properly restrict mapping page zero. A local privileged attacker could
use this to execute arbitrary code. (CVE-2017-5669)

Alexander Popov discovered that a race condition existed in the Stream
Control Transmission Protocol (SCTP) implementation in the Linux kernel. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2017-5986)

Dmitry Vyukov discovered that the Linux kernel did not properly handle TCP
packets with the URG flag. A remote attacker could use this to cause a
denial of service. (CVE-2017-6214)

Andrey Konovalov discovered that the LLC subsystem in the Linux kernel did
not properly set up a destructor in certain situations. A local attacker
could use this to cause a denial of service (system crash). (CVE-2017-6345)

It was discovered that a race condition existed in the AF_PACKET handling
code in the Linux kernel. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2017-6346)

Andrey Konovalov discovered that the IP layer in the Linux kernel made
improper assumptions about internal data layout when performing checksums.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2017-6347)

Dmitry Vyukov discovered race conditions in the Infrared (IrDA) subsystem
in the Linux kernel. A local attacker could use this to cause a denial of
service (deadlock). (CVE-2017-6348)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gke, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1012-gke", ver:"4.4.0-1012.12", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1016-aws", ver:"4.4.0-1016.25", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1054-raspi2", ver:"4.4.0-1054.61", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1057-snapdragon", ver:"4.4.0-1057.61", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-75-generic", ver:"4.4.0-75.96", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-75-generic-lpae", ver:"4.4.0-75.96", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-75-lowlatency", ver:"4.4.0-75.96", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-75-powerpc-e500mc", ver:"4.4.0-75.96", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-75-powerpc-smp", ver:"4.4.0-75.96", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-75-powerpc64-smp", ver:"4.4.0-75.96", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1016.19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.75.81", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.4.0.75.81", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.4.0.1012.14", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.75.81", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"4.4.0.75.81", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"4.4.0.75.81", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"4.4.0.75.81", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.4.0.1054.55", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.4.0.1057.50", rls:"UBUNTU16.04 LTS"))) {
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
