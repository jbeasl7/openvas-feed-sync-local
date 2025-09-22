# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843466");
  script_cve_id("CVE-2017-11334", "CVE-2017-13672", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15118", "CVE-2017-15119", "CVE-2017-15124", "CVE-2017-15268", "CVE-2017-15289", "CVE-2017-16845");
  script_tag(name:"creation_date", value:"2018-03-06 07:39:40 +0000 (Tue, 06 Mar 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 17:42:19 +0000 (Thu, 10 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-3575-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3575-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3575-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1752761");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-3575-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3575-1 fixed vulnerabilities in QEMU. The fix for CVE-2017-11334 caused
a regression in Xen environments. This update removes the problematic fix
pending further investigation.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that QEMU incorrectly handled guest ram. A privileged
 attacker inside the guest could use this issue to cause QEMU to crash,
 resulting in a denial of service. This issue only affected Ubuntu 14.04 LTS
 and Ubuntu 16.04 LTS. (CVE-2017-11334)

 David Buchanan discovered that QEMU incorrectly handled the VGA device. A
 privileged attacker inside the guest could use this issue to cause QEMU to
 crash, resulting in a denial of service. This issue was only addressed in
 Ubuntu 17.10. (CVE-2017-13672)

 Thomas Garnier discovered that QEMU incorrectly handled multiboot. An
 attacker could use this issue to cause QEMU to crash, resulting in a denial
 of service, or possibly execute arbitrary code on the host. In the default
 installation, when QEMU is used with libvirt, attackers would be isolated
 by the libvirt AppArmor profile. This issue only affected Ubuntu 14.04 LTS
 and Ubuntu 16.04 LTS. (CVE-2017-14167)

 Tuomas Tynkkynen discovered that QEMU incorrectly handled VirtFS directory
 sharing. An attacker could use this issue to obtain sensitive information
 from host memory. (CVE-2017-15038)

 Eric Blake discovered that QEMU incorrectly handled memory in the
 NBD server. An attacker could use this issue to cause the NBD server to
 crash, resulting in a denial of service. This issue only affected Ubuntu
 17.10. (CVE-2017-15118)

 Eric Blake discovered that QEMU incorrectly handled certain options to the
 NBD server. An attacker could use this issue to cause the NBD server to
 crash, resulting in a denial of service. This issue only affected Ubuntu
 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2017-15119)

 Daniel Berrange discovered that QEMU incorrectly handled the VNC server. A
 remote attacker could possibly use this issue to consume memory, resulting
 in a denial of service. This issue was only addressed in Ubuntu 17.10.
 (CVE-2017-15124)

 Carl Brassey discovered that QEMU incorrectly handled certain websockets. A
 remote attacker could possibly use this issue to consume memory, resulting
 in a denial of service. This issue only affected Ubuntu 17.10.
 (CVE-2017-15268)

 Guoxiang Niu discovered that QEMU incorrectly handled the Cirrus VGA
 device. A privileged attacker inside the guest could use this issue to
 cause QEMU to crash, resulting in a denial of service. (CVE-2017-15289)

 Cyrille Chatras discovered that QEMU incorrectly handled certain PS2 values
 during migration. An attacker could possibly use this issue to cause QEMU
 to crash, resulting in a denial of service, or possibly execute arbitrary
 code. This issue only affected Ubuntu 16.04 LTS and Ubuntu 17.10.
 (CVE-2017-16845)

 It was discovered that QEMU ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"2.0.0+dfsg-2ubuntu1.40", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.5+dfsg-5ubuntu10.24", rls:"UBUNTU16.04 LTS"))) {
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
