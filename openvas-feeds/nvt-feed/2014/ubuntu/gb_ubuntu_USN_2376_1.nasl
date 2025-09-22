# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842003");
  script_cve_id("CVE-2014-3181", "CVE-2014-3182", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-6410", "CVE-2014-6416", "CVE-2014-6417", "CVE-2014-6418");
  script_tag(name:"creation_date", value:"2014-10-10 04:11:29 +0000 (Fri, 10 Oct 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2376-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2376-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2376-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2376-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steven Vittitoe reported multiple stack buffer overflows in Linux kernel's
magicmouse HID driver. A physically proximate attacker could exploit this
flaw to cause a denial of service (system crash) or possibly execute
arbitrary code via specially crafted devices. (CVE-2014-3181)

A bounds check error was discovered in the driver for the Logitech Unifying
receivers and devices. A physically proximate attacker could exploit this
flaw to cause a denial of service (invalid kfree) or to execute
arbitrary code. (CVE-2014-3182)

Ben Hawkes reported some off by one errors for report descriptors in the
Linux kernel's HID stack. A physically proximate attacker could exploit
these flaws to cause a denial of service (out-of-bounds write) via a
specially crafted device. (CVE-2014-3184)

Several bounds check flaws allowing for buffer overflows were discovered in
the Linux kernel's Whiteheat USB serial driver. A physically proximate
attacker could exploit these flaws to cause a denial of service (system
crash) via a specially crafted device. (CVE-2014-3185)

Steven Vittitoe reported a buffer overflow in the Linux kernel's PicoLCD
HID device driver. A physically proximate attacker could exploit this flaw
to cause a denial of service (system crash) or possibly execute arbitrary
code via a specially craft device. (CVE-2014-3186)

A flaw was discovered in the Linux kernel's UDF filesystem (used on some
CD-ROMs and DVDs) when processing indirect ICBs. An attacker who can cause
CD, DVD or image file with a specially crafted inode to be mounted can
cause a denial of service (infinite loop or stack consumption).
(CVE-2014-6410)

James Eckersall discovered a buffer overflow in the Ceph filesystem in the
Linux kernel. A remote attacker could exploit this flaw to cause a denial
of service (memory consumption and panic) or possibly have other
unspecified impact via a long unencrypted auth ticket. (CVE-2014-6416)

James Eckersall discovered a flaw in the handling of memory allocation
failures in the Ceph filesystem. A remote attacker could exploit this flaw
to cause a denial of service (system crash) or possibly have unspecified
other impact. (CVE-2014-6417)

James Eckersall discovered a flaw in how the Ceph filesystem validates auth
replies. A remote attacker could exploit this flaw to cause a denial of
service (system crash) or possibly have other unspecified impact.
(CVE-2014-6418)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-70-generic", ver:"3.2.0-70.105", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-70-generic-pae", ver:"3.2.0-70.105", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-70-highbank", ver:"3.2.0-70.105", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-70-omap", ver:"3.2.0-70.105", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-70-powerpc-smp", ver:"3.2.0-70.105", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-70-powerpc64-smp", ver:"3.2.0-70.105", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-70-virtual", ver:"3.2.0-70.105", rls:"UBUNTU12.04 LTS"))) {
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
