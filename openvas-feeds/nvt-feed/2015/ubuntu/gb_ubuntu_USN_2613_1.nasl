# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842232");
  script_cve_id("CVE-2014-9715", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-3331");
  script_tag(name:"creation_date", value:"2015-06-09 09:09:59 +0000 (Tue, 09 Jun 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2613-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2613-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2613-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-2613-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vincent Tondellier discovered an integer overflow in the Linux kernel's
netfilter connection tracking accounting of loaded extensions. An attacker
on the local area network (LAN) could potential exploit this flaw to cause
a denial of service (system crash of targeted system). (CVE-2014-9715)

Jan Beulich discovered the Xen virtual machine subsystem of the Linux
kernel did not properly restrict access to PCI command registers. A local
guest user could exploit this flaw to cause a denial of service (host
crash). (CVE-2015-2150)

A privilege escalation was discovered in the fork syscall via the int80
entry on 64 bit kernels with 32 bit emulation support. An unprivileged
local attacker could exploit this flaw to increase their privileges on the
system. (CVE-2015-2830)

A memory corruption issue was discovered in AES decryption when using the
Intel AES-NI accelerated code path. A remote attacker could exploit this
flaw to cause a denial of service (system crash) or potentially escalate
privileges on Intel base machines with AEC-GCM mode IPSec security
association. (CVE-2015-3331)");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-53-generic", ver:"3.13.0-53.87~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-53-generic-lpae", ver:"3.13.0-53.87~precise1", rls:"UBUNTU12.04 LTS"))) {
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
