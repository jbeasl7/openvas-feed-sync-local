# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840920");
  script_cve_id("CVE-2011-2498", "CVE-2011-2518", "CVE-2011-3353", "CVE-2011-4097", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0044", "CVE-2012-0207");
  script_tag(name:"creation_date", value:"2012-03-07 05:49:56 +0000 (Wed, 07 Mar 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-05-17 16:37:00 +0000 (Thu, 17 May 2012)");

  script_name("Ubuntu: Security Advisory (USN-1386-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1386-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1386-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-backport-natty' package(s) announced via the USN-1386-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The linux kernel did not properly account for PTE pages when deciding which
task to kill in out of memory conditions. A local, unprivileged could
exploit this flaw to cause a denial of service. (CVE-2011-2498)

A flaw was discovered in the TOMOYO LSM's handling of mount system calls.
An unprivileged user could oops the system causing a denial of service.
(CVE-2011-2518)

Han-Wen Nienhuys reported a flaw in the FUSE kernel module. A local user
who can mount a FUSE file system could cause a denial of service.
(CVE-2011-3353)

A bug was discovered in the Linux kernel's calculation of OOM (Out of
memory) scores, that would result in the wrong process being killed. A user
could use this to kill the process with the highest OOM score, even if that
process belongs to another user or the system. (CVE-2011-4097)

A flaw was found in KVM's Programmable Interval Timer (PIT). When a virtual
interrupt control is not available a local user could use this to cause a
denial of service by starting a timer. (CVE-2011-4622)

A flaw was discovered in the XFS filesystem. If a local user mounts a
specially crafted XFS image it could potential execute arbitrary code on
the system. (CVE-2012-0038)

Chen Haogang discovered an integer overflow that could result in memory
corruption. A local unprivileged user could use this to crash the system.
(CVE-2012-0044)

A flaw was found in the linux kernels IPv4 IGMP query processing. A remote
attacker could exploit this to cause a denial of service. (CVE-2012-0207)");

  script_tag(name:"affected", value:"'linux-lts-backport-natty' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-13-generic", ver:"2.6.38-13.56~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-13-generic-pae", ver:"2.6.38-13.56~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-13-server", ver:"2.6.38-13.56~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-13-virtual", ver:"2.6.38-13.56~lucid1", rls:"UBUNTU10.04 LTS"))) {
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
