# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841997");
  script_cve_id("CVE-2014-3184", "CVE-2014-3185", "CVE-2014-6410");
  script_tag(name:"creation_date", value:"2014-10-10 04:09:42 +0000 (Fri, 10 Oct 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2375-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2375-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2375-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-2375-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ben Hawkes reported some off by one errors for report descriptors in the
Linux kernel's HID stack. A physically proximate attacker could exploit
these flaws to cause a denial of service (out-of-bounds write) via a
specially crafted device. (CVE-2014-3184)

Several bounds check flaws allowing for buffer overflows were discovered in
the Linux kernel's Whiteheat USB serial driver. A physically proximate
attacker could exploit these flaws to cause a denial of service (system
crash) via a specially crafted device. (CVE-2014-3185)

A flaw was discovered in the Linux kernel's UDF filesystem (used on some
CD-ROMs and DVDs) when processing indirect ICBs. An attacker who can cause
CD, DVD or image file with a specially crafted inode to be mounted can
cause a denial of service (infinite loop or stack consumption).
(CVE-2014-6410)");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-371-ec2", ver:"2.6.32-371.87", rls:"UBUNTU10.04 LTS"))) {
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
