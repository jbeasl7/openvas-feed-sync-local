# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843509");
  script_cve_id("CVE-2017-0861", "CVE-2017-1000407", "CVE-2017-15129", "CVE-2017-16994", "CVE-2017-17448", "CVE-2017-17450", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-17807", "CVE-2018-1000026", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5344", "CVE-2018-8043");
  script_tag(name:"creation_date", value:"2018-04-25 06:37:19 +0000 (Wed, 25 Apr 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-01 20:23:04 +0000 (Thu, 01 Feb 2018)");

  script_name("Ubuntu: Security Advisory (USN-3632-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3632-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3632-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-3632-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition leading to a use-after-free
vulnerability existed in the ALSA PCM subsystem of the Linux kernel. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2017-0861)

It was discovered that the KVM implementation in the Linux kernel allowed
passthrough of the diagnostic I/O port 0x80. An attacker in a guest VM
could use this to cause a denial of service (system crash) in the host OS.
(CVE-2017-1000407)

It was discovered that a use-after-free vulnerability existed in the
network namespaces implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-15129)

It was discovered that the HugeTLB component of the Linux kernel did not
properly handle holes in hugetlb ranges. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2017-16994)

It was discovered that the netfilter component of the Linux did not
properly restrict access to the connection tracking helpers list. A local
attacker could use this to bypass intended access restrictions.
(CVE-2017-17448)

It was discovered that the netfilter passive OS fingerprinting (xt_osf)
module did not properly perform access control checks. A local attacker
could improperly modify the system-wide OS fingerprint list.
(CVE-2017-17450)

Dmitry Vyukov discovered that the KVM implementation in the Linux kernel
contained an out-of-bounds read when handling memory-mapped I/O. A local
attacker could use this to expose sensitive information. (CVE-2017-17741)

It was discovered that the Salsa20 encryption algorithm implementations in
the Linux kernel did not properly handle zero-length inputs. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-17805)

It was discovered that the HMAC implementation did not validate the state
of the underlying cryptographic hash algorithm. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-17806)

It was discovered that the keyring implementation in the Linux kernel did
not properly check permissions when a key request was performed on a task's
default keyring. A local attacker could use this to add keys to
unauthorized keyrings. (CVE-2017-17807)

It was discovered that the Broadcom NetXtremeII ethernet driver in the
Linux kernel did not properly validate Generic Segment Offload (GSO) packet
sizes. An attacker could use this to cause a denial of service (interface
unavailability). (CVE-2018-1000026)

It was discovered that the Reliable Datagram Socket (RDS) implementation in
the Linux kernel contained an out-of-bounds write during RDMA page
allocation. An attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-5332)

Mohamed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-1014-azure", ver:"4.13.0-1014.17", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.13.0.1014.16", rls:"UBUNTU16.04 LTS"))) {
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
