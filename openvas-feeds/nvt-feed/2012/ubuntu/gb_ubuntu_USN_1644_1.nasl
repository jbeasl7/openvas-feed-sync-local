# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841233");
  script_cve_id("CVE-2012-0957", "CVE-2012-4508", "CVE-2012-4565", "CVE-2012-6536", "CVE-2012-6537", "CVE-2012-6538", "CVE-2012-6657", "CVE-2013-0309", "CVE-2013-1826", "CVE-2013-1928");
  script_tag(name:"creation_date", value:"2012-12-04 04:18:28 +0000 (Tue, 04 Dec 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1644-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1644-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1644-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1644-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brad Spengler discovered a flaw in the Linux kernel's uname system call. An
unprivileged user could exploit this flaw to read kernel stack memory.
(CVE-2012-0957)

Dmitry Monakhov reported a race condition flaw the Linux ext4 filesystem
that can expose stale data. An unprivileged user could exploit this flaw to
cause an information leak. (CVE-2012-4508)

Rodrigo Freire discovered a flaw in the Linux kernel's TCP illinois
congestion control algorithm. A local attacker could use this to cause a
denial of service. (CVE-2012-4565)

Mathias Krause discovered a flaw in the Linux kernel's XFRM netlink
interface. A local user with the NET_ADMIN capability could exploit this
flaw to leak the contents of kernel memory. (CVE-2012-6536)

Mathias Krause discovered several errors in the Linux kernel's xfrm_user
implementation. A local attacker could exploit these flaws to examine parts
of kernel memory. (CVE-2012-6537)

Mathias Krause discovered an information leak in the Linux kernel's
xfrm_user copy_to_user_auth function. A local user could exploit this flaw
to examine parts of kernel heap memory. (CVE-2012-6538)

Dave Jones discovered that the Linux kernel's socket subsystem does not
correctly ensure the keepalive action is associated with a stream socket. A
local user could exploit this flaw to cause a denial of service (system
crash) by creating a raw socket. (CVE-2012-6657)

A flaw was discovered in the Linux kernels handling of memory ranges with
PROT_NONE when transparent hugepages are in use. An unprivileged local user
could exploit this flaw to cause a denial of service (crash the system).
(CVE-2013-0309)

Mathias Krause discovered a flaw in xfrm_user in the Linux kernel. A local
attacker with NET_ADMIN capability could potentially exploit this flaw to
escalate privileges. (CVE-2013-1826)

An information leak was discovered in the Linux kernel's /dev/dvb device. A
local user could exploit this flaw to obtain sensitive information from the
kernel's stack memory. (CVE-2013-1928)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-34-generic", ver:"3.2.0-34.53", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-34-generic-pae", ver:"3.2.0-34.53", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-34-highbank", ver:"3.2.0-34.53", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-34-omap", ver:"3.2.0-34.53", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-34-powerpc-smp", ver:"3.2.0-34.53", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-34-powerpc64-smp", ver:"3.2.0-34.53", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-34-virtual", ver:"3.2.0-34.53", rls:"UBUNTU12.04 LTS"))) {
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
