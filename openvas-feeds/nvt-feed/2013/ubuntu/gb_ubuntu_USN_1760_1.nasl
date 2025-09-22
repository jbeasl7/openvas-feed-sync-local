# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841359");
  script_cve_id("CVE-2013-0216", "CVE-2013-0217", "CVE-2013-0228", "CVE-2013-0268", "CVE-2013-0311", "CVE-2013-0349", "CVE-2013-1773");
  script_tag(name:"creation_date", value:"2013-03-15 04:35:24 +0000 (Fri, 15 Mar 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1760-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1760-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1760-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-backport-oneiric' package(s) announced via the USN-1760-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A failure to validate input was discovered in the Linux kernel's Xen
netback (network backend) driver. A user in a guest OS may exploit this
flaw to cause a denial of service to the guest OS and other guest domains.
(CVE-2013-0216)

A memory leak was discovered in the Linux kernel's Xen netback (network
backend) driver. A user in a guest OS could trigger this flaw to cause a
denial of service on the system. (CVE-2013-0217)

Andrew Jones discovered a flaw with the xen_iret function in Linux kernel's
Xen virtualizeation. In the 32-bit Xen paravirt platform an unprivileged
guest OS user could exploit this flaw to cause a denial of service (crash
the system) or gain guest OS privilege. (CVE-2013-0228)

A flaw was reported in the permission checks done by the Linux kernel for
/dev/cpu/*/msr. A local root user with all capabilities dropped could
exploit this flaw to execute code with full root capabilities.
(CVE-2013-0268)

A flaw was discovered in the Linux kernel's vhost driver used to accelerate
guest networking in KVM based virtual machines. A privileged guest user
could exploit this flaw to crash the host system. (CVE-2013-0311)

An information leak was discovered in the Linux kernel's Bluetooth stack
when HIDP (Human Interface Device Protocol) support is enabled. A local
unprivileged user could exploit this flaw to cause an information leak from
the kernel. (CVE-2013-0349)

A flaw was discovered on the Linux kernel's VFAT filesystem driver when a
disk is mounted with the utf8 option (this is the default on Ubuntu). On a
system where disks/images can be auto-mounted or a FAT filesystem is
mounted an unprivileged user can exploit the flaw to gain root privileges.
(CVE-2013-1773)");

  script_tag(name:"affected", value:"'linux-lts-backport-oneiric' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-32-generic", ver:"3.0.0-32.50~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-32-generic-pae", ver:"3.0.0-32.50~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-32-server", ver:"3.0.0-32.50~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-32-virtual", ver:"3.0.0-32.50~lucid1", rls:"UBUNTU10.04 LTS"))) {
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
