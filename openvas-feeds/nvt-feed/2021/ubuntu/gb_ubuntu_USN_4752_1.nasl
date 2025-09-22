# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844847");
  script_cve_id("CVE-2020-10135", "CVE-2020-14314", "CVE-2020-15436", "CVE-2020-15437", "CVE-2020-24490", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25704", "CVE-2020-27152", "CVE-2020-27815", "CVE-2020-28588", "CVE-2020-28915", "CVE-2020-29368", "CVE-2020-29369", "CVE-2020-29371", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-35508");
  script_tag(name:"creation_date", value:"2021-02-26 04:00:29 +0000 (Fri, 26 Feb 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-11 02:06:30 +0000 (Fri, 11 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4752-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4752-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4752-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.6' package(s) announced via the USN-4752-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniele Antonioli, Nils Ole Tippenhauer, and Kasper Rasmussen discovered
that legacy pairing and secure-connections pairing authentication in the
Bluetooth protocol could allow an unauthenticated user to complete
authentication without pairing credentials via adjacent access. A
physically proximate attacker could use this to impersonate a previously
paired Bluetooth device. (CVE-2020-10135)

Jay Shin discovered that the ext4 file system implementation in the Linux
kernel did not properly handle directory access with broken indexing,
leading to an out-of-bounds read vulnerability. A local attacker could use
this to cause a denial of service (system crash). (CVE-2020-14314)

It was discovered that the block layer implementation in the Linux kernel
did not properly perform reference counting in some situations, leading to
a use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash). (CVE-2020-15436)

It was discovered that the serial port driver in the Linux kernel did not
properly initialize a pointer in some situations. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2020-15437)

Andy Nguyen discovered that the Bluetooth HCI event packet parser in the
Linux kernel did not properly handle event advertisements of certain sizes,
leading to a heap-based buffer overflow. A physically proximate remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2020-24490)

It was discovered that the NFS client implementation in the Linux kernel
did not properly perform bounds checking before copying security labels in
some situations. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2020-25212)

It was discovered that the Rados block device (rbd) driver in the Linux
kernel did not properly perform privilege checks for access to rbd devices
in some situations. A local attacker could use this to map or unmap rbd
block devices. (CVE-2020-25284)

It was discovered that the block layer subsystem in the Linux kernel did
not properly handle zero-length requests. A local attacker could use this
to cause a denial of service. (CVE-2020-25641)

It was discovered that the HDLC PPP implementation in the Linux kernel did
not properly validate input in some situations. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2020-25643)

Kiyin (Yin Liang ) discovered that the perf subsystem in the Linux kernel did
not properly deallocate memory in some situations. A privileged attacker
could use this to cause a denial of service (kernel memory exhaustion).
(CVE-2020-25704)

It was discovered that the KVM hypervisor in the Linux kernel did not
properly handle interrupts in certain situations. A local attacker in a
guest VM could ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-oem-5.6' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.6.0-1048-oem", ver:"5.6.0-1048.52", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.6.0.1048.44", rls:"UBUNTU20.04 LTS"))) {
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
