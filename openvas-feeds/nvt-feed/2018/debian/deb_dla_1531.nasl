# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891531");
  script_cve_id("CVE-2018-10902", "CVE-2018-10938", "CVE-2018-13099", "CVE-2018-14609", "CVE-2018-14617", "CVE-2018-14633", "CVE-2018-14678", "CVE-2018-14734", "CVE-2018-15572", "CVE-2018-15594", "CVE-2018-16276", "CVE-2018-16658", "CVE-2018-17182", "CVE-2018-6554", "CVE-2018-6555", "CVE-2018-7755", "CVE-2018-9363", "CVE-2018-9516");
  script_tag(name:"creation_date", value:"2018-10-03 22:00:00 +0000 (Wed, 03 Oct 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-12 22:07:35 +0000 (Wed, 12 Dec 2018)");

  script_name("Debian: Security Advisory (DLA-1531-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1531-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1531-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.9' package(s) announced via the DLA-1531-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2018-6554

A memory leak in the irda_bind function in the irda subsystem was discovered. A local user can take advantage of this flaw to cause a denial of service (memory consumption).

CVE-2018-6555

A flaw was discovered in the irda_setsockopt function in the irda subsystem, allowing a local user to cause a denial of service (use-after-free and system crash).

CVE-2018-7755

Brian Belleville discovered a flaw in the fd_locked_ioctl function in the floppy driver in the Linux kernel. The floppy driver copies a kernel pointer to user memory in response to the FDGETPRM ioctl. A local user with access to a floppy drive device can take advantage of this flaw to discover the location kernel code and data.

CVE-2018-9363

It was discovered that the Bluetooth HIDP implementation did not correctly check the length of received report messages. A paired HIDP device could use this to cause a buffer overflow, leading to denial of service (memory corruption or crash) or potentially remote code execution.

CVE-2018-9516

It was discovered that the HID events interface in debugfs did not correctly limit the length of copies to user buffers. A local user with access to these files could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation. However, by default debugfs is only accessible by the root user.

CVE-2018-10902

It was discovered that the rawmidi kernel driver does not protect against concurrent access which leads to a double-realloc (double free) flaw. A local attacker can take advantage of this issue for privilege escalation.

CVE-2018-10938

Yves Younan from Cisco reported that the Cipso IPv4 module did not correctly check the length of IPv4 options. On custom kernels with CONFIG_NETLABEL enabled, a remote attacker could use this to cause a denial of service (hang).

CVE-2018-13099

Wen Xu from SSLab at Gatech reported a use-after-free bug in the F2FS implementation. An attacker able to mount a crafted F2FS volume could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2018-14609

Wen Xu from SSLab at Gatech reported a potential null pointer dereference in the F2FS implementation. An attacker able to mount arbitrary F2FS volumes could use this to cause a denial of service (crash).

CVE-2018-14617

Wen Xu from SSLab at Gatech reported a potential null pointer dereference in the HFS+ implementation. An attacker able to mount arbitrary HFS+ volumes could use this to cause a denial of service (crash).

CVE-2018-14633

Vincent Pelletier discovered a stack-based buffer overflow flaw in the chap_server_compute_md5() function in the iSCSI target code. An unauthenticated remote attacker can take advantage of this flaw to cause ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-4.9' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-arm", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-686", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-armel", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-armhf", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-all-i386", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-armmp", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-armmp-lpae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-common", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-common-rt", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-marvell", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-rt-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.8-rt-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-686-pae-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-amd64-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-armmp", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-armmp-lpae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-marvell", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-686-pae", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-686-pae-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-amd64", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.8-rt-amd64-dbg", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.8", ver:"4.9.110-3+deb9u5~deb8u1", rls:"DEB8"))) {
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
