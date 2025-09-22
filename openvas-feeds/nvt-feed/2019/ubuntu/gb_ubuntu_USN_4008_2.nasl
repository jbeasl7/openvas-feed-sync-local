# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844041");
  script_cve_id("CVE-2019-11190");
  script_tag(name:"creation_date", value:"2019-06-06 02:00:43 +0000 (Thu, 06 Jun 2019)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-12 13:56:26 +0000 (Fri, 12 Apr 2019)");

  script_name("Ubuntu: Security Advisory (USN-4008-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4008-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4008-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apparmor' package(s) announced via the USN-4008-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4008-1 fixed multiple security issues in the Linux kernel. This update
provides the corresponding changes to AppArmor policy for correctly
operating under the Linux kernel with fixes for CVE-2019-11190. Without
these changes, some profile transitions may be unintentionally denied due
to missing mmap ('m') rules.

Original advisory details:

 Robert Swiecki discovered that the Linux kernel did not properly apply
 Address Space Layout Randomization (ASLR) in some situations for setuid elf
 binaries. A local attacker could use this to improve the chances of
 exploiting an existing vulnerability in a setuid elf binary.
 (CVE-2019-11190)

 It was discovered that a null pointer dereference vulnerability existed in
 the LSI Logic MegaRAID driver in the Linux kernel. A local attacker could
 use this to cause a denial of service (system crash). (CVE-2019-11810)

 It was discovered that a race condition leading to a use-after-free existed
 in the Reliable Datagram Sockets (RDS) protocol implementation in the Linux
 kernel. The RDS protocol is disabled via blocklist by default in Ubuntu. If
 enabled, a local attacker could use this to cause a denial of service
 (system crash) or possibly execute arbitrary code. (CVE-2019-11815)

 Federico Manuel Bento discovered that the Linux kernel did not properly
 apply Address Space Layout Randomization (ASLR) in some situations for
 setuid a.out binaries. A local attacker could use this to improve the
 chances of exploiting an existing vulnerability in a setuid a.out binary.
 (CVE-2019-11191)

 As a hardening measure, this update disables a.out support.");

  script_tag(name:"affected", value:"'apparmor' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apparmor-profiles", ver:"2.10.95-0ubuntu2.11", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-apparmor", ver:"2.10.95-0ubuntu2.11", rls:"UBUNTU16.04 LTS"))) {
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
