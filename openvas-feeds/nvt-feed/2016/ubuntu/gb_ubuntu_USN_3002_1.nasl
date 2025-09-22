# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842788");
  script_cve_id("CVE-2015-4004", "CVE-2016-1583", "CVE-2016-2117", "CVE-2016-2187", "CVE-2016-3672", "CVE-2016-3951", "CVE-2016-3955", "CVE-2016-3961", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4581");
  script_tag(name:"creation_date", value:"2016-06-11 03:25:57 +0000 (Sat, 11 Jun 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-05 17:21:17 +0000 (Tue, 05 Jul 2016)");

  script_name("Ubuntu: Security Advisory (USN-3002-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3002-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3002-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-wily' package(s) announced via the USN-3002-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Justin Yackoski discovered that the Atheros L2 Ethernet Driver in the Linux
kernel incorrectly enables scatter/gather I/O. A remote attacker could use
this to obtain potentially sensitive information from kernel memory.
(CVE-2016-2117)

Jann Horn discovered that eCryptfs improperly attempted to use the mmap()
handler of a lower filesystem that did not implement one, causing a
recursive page fault to occur. A local unprivileged attacker could use to
cause a denial of service (system crash) or possibly execute arbitrary code
with administrative privileges. (CVE-2016-1583)

Jason A. Donenfeld discovered multiple out-of-bounds reads in the OZMO USB
over wifi device drivers in the Linux kernel. A remote attacker could use
this to cause a denial of service (system crash) or obtain potentially
sensitive information from kernel memory. (CVE-2015-4004)

Ralf Spenneberg discovered that the Linux kernel's GTCO digitizer USB
device driver did not properly validate endpoint descriptors. An attacker
with physical access could use this to cause a denial of service (system
crash). (CVE-2016-2187)

Hector Marco and Ismael Ripoll discovered that the Linux kernel would
improperly disable Address Space Layout Randomization (ASLR) for x86
processes running in 32 bit mode if stack-consumption resource limits were
disabled. A local attacker could use this to make it easier to exploit an
existing vulnerability in a setuid/setgid program. (CVE-2016-3672)

Andrey Konovalov discovered that the CDC Network Control Model USB driver
in the Linux kernel did not cancel work events queued if a later error
occurred, resulting in a use-after-free. An attacker with physical access
could use this to cause a denial of service (system crash). (CVE-2016-3951)

It was discovered that an out-of-bounds write could occur when handling
incoming packets in the USB/IP implementation in the Linux kernel. A remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2016-3955)

Vitaly Kuznetsov discovered that the Linux kernel did not properly suppress
hugetlbfs support in X86 paravirtualized guests. An attacker in the guest
OS could cause a denial of service (guest system crash). (CVE-2016-3961)

Kangjie Lu discovered an information leak in the ANSI/IEEE 802.2 LLC type 2
Support implementations in the Linux kernel. A local attacker could use
this to obtain potentially sensitive information from kernel memory.
(CVE-2016-4485)

Kangjie Lu discovered an information leak in the routing netlink socket
interface (rtnetlink) implementation in the Linux kernel. A local attacker
could use this to obtain potentially sensitive information from kernel
memory. (CVE-2016-4486)

Jann Horn discovered that the InfiniBand interfaces within the Linux kernel
could be coerced into overwriting kernel memory. A local unprivileged
attacker could use this to possibly gain administrative ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-lts-wily' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-38-generic", ver:"4.2.0-38.45~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-38-generic-lpae", ver:"4.2.0-38.45~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-38-lowlatency", ver:"4.2.0-38.45~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-38-powerpc-e500mc", ver:"4.2.0-38.45~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-38-powerpc-smp", ver:"4.2.0-38.45~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-38-powerpc64-emb", ver:"4.2.0-38.45~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-38-powerpc64-smp", ver:"4.2.0-38.45~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
