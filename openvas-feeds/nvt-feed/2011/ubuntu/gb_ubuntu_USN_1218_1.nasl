# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840760");
  script_cve_id("CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4251", "CVE-2010-4805", "CVE-2011-1020", "CVE-2011-1493", "CVE-2011-1577", "CVE-2011-1585", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-2182", "CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2909", "CVE-2011-2918", "CVE-2011-3637", "CVE-2011-4914");
  script_tag(name:"creation_date", value:"2011-09-30 14:02:57 +0000 (Fri, 30 Sep 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2011-05-26 18:06:00 +0000 (Thu, 26 May 2011)");

  script_name("Ubuntu: Security Advisory (USN-1218-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1218-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1218-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1218-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that multiple terminal ioctls did not correctly
initialize structure memory. A local attacker could exploit this to read
portions of kernel stack memory, leading to a loss of privacy.
(CVE-2010-4076, CVE-2010-4077)

Alex Shi and Eric Dumazet discovered that the network stack did not
correctly handle packet backlogs. A remote attacker could exploit this by
sending a large amount of network traffic to cause the system to run out of
memory, leading to a denial of service. (CVE-2010-4251, CVE-2010-4805)

It was discovered that the /proc filesystem did not correctly handle
permission changes when programs executed. A local attacker could hold open
files to examine details about programs running with higher privileges,
potentially increasing the chances of exploiting additional
vulnerabilities. (CVE-2011-1020)

Dan Rosenberg discovered that the X.25 Rose network stack did not correctly
handle certain fields. If a system was running with Rose enabled, a remote
attacker could send specially crafted traffic to gain root privileges.
(CVE-2011-1493)

Timo Warns discovered that the GUID partition parsing routines did not
correctly validate certain structures. A local attacker with physical
access could plug in a specially crafted block device to crash the system,
leading to a denial of service. (CVE-2011-1577)

It was discovered that CIFS incorrectly handled authentication. When a user
had a CIFS share mounted that required authentication, a local user could
mount the same share without knowing the correct password. (CVE-2011-1585)

It was discovered that the GRE protocol incorrectly handled netns
initialization. A remote attacker could send a packet while the ip_gre
module was loading, and crash the system, leading to a denial of service.
(CVE-2011-1767)

It was discovered that the IP/IP protocol incorrectly handled netns
initialization. A remote attacker could send a packet while the ipip module
was loading, and crash the system, leading to a denial of service.
(CVE-2011-1768)

Ben Hutchings reported a flaw in the kernel's handling of corrupt LDM
partitions. A local user could exploit this to cause a denial of service or
escalate privileges. (CVE-2011-2182)

Andrea Righi discovered a race condition in the KSM memory merging support.
If KSM was being used, a local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2011-2183)

Dan Rosenberg discovered that the IPv4 diagnostic routines did not
correctly validate certain requests. A local attacker could exploit this to
consume CPU resources, leading to a denial of service. (CVE-2011-2213)

Vasiliy Kulikov discovered that taskstats listeners were not correctly
handled. A local attacker could exploit this to exhaust memory and CPU
resources, leading to a denial of service. (CVE-2011-2484)

It was discovered that Bluetooth l2cap and rfcomm did not correctly
initialize structures. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-386", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-generic", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-generic-pae", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-ia64", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-lpia", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-powerpc", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-powerpc-smp", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-powerpc64-smp", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-preempt", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-server", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-sparc64", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-sparc64-smp", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-versatile", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-34-virtual", ver:"2.6.32-34.77", rls:"UBUNTU10.04 LTS"))) {
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
