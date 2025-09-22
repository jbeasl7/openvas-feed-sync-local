# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840605");
  script_cve_id("CVE-2009-4895", "CVE-2010-0435", "CVE-2010-2066", "CVE-2010-2226", "CVE-2010-2248", "CVE-2010-2478", "CVE-2010-2495", "CVE-2010-2521", "CVE-2010-2524", "CVE-2010-2537", "CVE-2010-2538", "CVE-2010-2798", "CVE-2010-2942", "CVE-2010-2943", "CVE-2010-2946", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2960", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3015", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3084", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3301", "CVE-2010-3310", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3477", "CVE-2010-3705", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3861", "CVE-2010-3874", "CVE-2010-3904", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4242", "CVE-2010-4243", "CVE-2010-4249", "CVE-2010-4256", "CVE-2010-4258", "CVE-2010-4655", "CVE-2011-0709");
  script_tag(name:"creation_date", value:"2011-03-07 05:45:55 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2010-10-01 15:56:00 +0000 (Fri, 01 Oct 2010)");

  script_name("Ubuntu: Security Advisory (USN-1083-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1083-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1083-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-backport-maverick' package(s) announced via the USN-1083-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that the RDS network protocol did not correctly
check certain parameters. A local attacker could exploit this gain root
privileges. (CVE-2010-3904)

Nelson Elhage discovered several problems with the Acorn Econet protocol
driver. A local user could cause a denial of service via a NULL pointer
dereference, escalate privileges by overflowing the kernel stack, and
assign Econet addresses to arbitrary interfaces. (CVE-2010-3848,
CVE-2010-3849, CVE-2010-3850)

Ben Hawkes discovered that the Linux kernel did not correctly filter
registers on 64bit kernels when performing 32bit system calls. On a 64bit
system, a local attacker could manipulate 32bit system calls to gain root
privileges. (CVE-2010-3301)

Al Viro discovered a race condition in the TTY driver. A local attacker
could exploit this to crash the system, leading to a denial of service.
(CVE-2009-4895)

Gleb Napatov discovered that KVM did not correctly check certain privileged
operations. A local attacker with access to a guest kernel could exploit
this to crash the host system, leading to a denial of service.
(CVE-2010-0435)

Dan Rosenberg discovered that the MOVE_EXT ext4 ioctl did not correctly
check file permissions. A local attacker could overwrite append-only files,
leading to potential data loss. (CVE-2010-2066)

Dan Rosenberg discovered that the swapexit xfs ioctl did not correctly
check file permissions. A local attacker could exploit this to read from
write-only files, leading to a loss of privacy. (CVE-2010-2226)

Suresh Jayaraman discovered that CIFS did not correctly validate certain
response packets. A remote attacker could send specially crafted traffic
that would crash the system, leading to a denial of service.
(CVE-2010-2248)

Ben Hutchings discovered that the ethtool interface did not correctly check
certain sizes. A local attacker could perform malicious ioctl calls that
could crash the system, leading to a denial of service. (CVE-2010-2478,
CVE-2010-3084)

James Chapman discovered that L2TP did not correctly evaluate checksum
capabilities. If an attacker could make malicious routing changes, they
could crash the system, leading to a denial of service. (CVE-2010-2495)

Neil Brown discovered that NFSv4 did not correctly check certain write
requests. A remote attacker could send specially crafted traffic that could
crash the system or possibly gain root privileges. (CVE-2010-2521)

David Howells discovered that DNS resolution in CIFS could be spoofed. A
local attacker could exploit this to control DNS replies, leading to a loss
of privacy and possible privilege escalation. (CVE-2010-2524)

Dan Rosenberg discovered that the btrfs filesystem did not correctly
validate permissions when using the clone function. A local attacker could
overwrite the contents of file handles that were opened for append-only, or
potentially read arbitrary contents, leading to a loss of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-lts-backport-maverick' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-25-generic", ver:"2.6.35-25.44~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-25-generic-pae", ver:"2.6.35-25.44~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-25-server", ver:"2.6.35-25.44~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-25-virtual", ver:"2.6.35-25.44~lucid1", rls:"UBUNTU10.04 LTS"))) {
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
