# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840997");
  script_cve_id("CVE-2011-4086", "CVE-2011-4347", "CVE-2012-0045", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-1146", "CVE-2012-1179", "CVE-2012-4398");
  script_tag(name:"creation_date", value:"2012-05-04 05:18:05 +0000 (Fri, 04 May 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-05-17 17:30:00 +0000 (Thu, 17 May 2012)");

  script_name("Ubuntu: Security Advisory (USN-1433-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1433-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1433-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-backport-oneiric' package(s) announced via the USN-1433-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Linux's kernels ext4 file system when mounted with
a journal. A local, unprivileged user could exploit this flaw to cause a
denial of service. (CVE-2011-4086)

Sasha Levin discovered a flaw in the permission checking for device
assignments requested via the kvm ioctl in the Linux kernel. A local user
could use this flaw to crash the system causing a denial of service.
(CVE-2011-4347)

Stephan Barwolf discovered a flaw in the KVM (kernel-based virtual
machine) subsystem of the Linux kernel. A local unprivileged user can crash
use this flaw to crash VMs causing a deny of service. (CVE-2012-0045)

A flaw was discovered in the Linux kernel's cifs file system. An
unprivileged local user could exploit this flaw to crash the system leading
to a denial of service. (CVE-2012-1090)

H. Peter Anvin reported a flaw in the Linux kernel that could crash the
system. A local user could exploit this flaw to crash the system.
(CVE-2012-1097)

A flaw was discovered in the Linux kernel's cgroups subset. A local
attacker could use this flaw to crash the system. (CVE-2012-1146)

A flaw was found in the Linux kernel's handling of paged memory. A local
unprivileged user, or a privileged user within a KVM guest, could exploit
this flaw to crash the system. (CVE-2012-1179)

Tetsuo Handa reported a flaw in the OOM (out of memory) killer of the Linux
kernel. A local unprivileged user can exploit this flaw to cause system
unstability and denial of services. (CVE-2012-4398)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-19-generic", ver:"3.0.0-19.33~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-19-generic-pae", ver:"3.0.0-19.33~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-19-server", ver:"3.0.0-19.33~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-19-virtual", ver:"3.0.0-19.33~lucid1", rls:"UBUNTU10.04 LTS"))) {
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
