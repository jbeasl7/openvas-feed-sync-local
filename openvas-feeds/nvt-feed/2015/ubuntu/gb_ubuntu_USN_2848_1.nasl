# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842580");
  script_cve_id("CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8709");
  script_tag(name:"creation_date", value:"2015-12-20 04:40:11 +0000 (Sun, 20 Dec 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-18 17:31:24 +0000 (Mon, 18 Apr 2016)");

  script_name("Ubuntu: Security Advisory (USN-2848-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2848-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2848-1");
  script_xref(name:"URL", value:"http://bugs.launchpad.net/bugs/1527374");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2848-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felix Wilhelm discovered a race condition in the Xen paravirtualized
drivers which can cause double fetch vulnerabilities. An attacker in the
paravirtualized guest could exploit this flaw to cause a denial of service
(crash the host) or potentially execute arbitrary code on the host.
(CVE-2015-8550)

Konrad Rzeszutek Wilk discovered the Xen PCI backend driver does not
perform consistency checks on the device's state. An attacker could exploit this
flaw to cause a denial of service (NULL dereference) on the host.
(CVE-2015-8551)

Konrad Rzeszutek Wilk discovered the Xen PCI backend driver does not
perform consistency checks on the device's state. An attacker could exploit this
flaw to cause a denial of service by flooding the logging system with
WARN() messages causing the initial domain to exhaust disk space.
(CVE-2015-8552)

Jann Horn discovered a ptrace issue with user namespaces in the Linux
kernel. The namespace owner could potentially exploit this flaw by ptracing
a root owned process entering the user namespace to elevate its privileges
and potentially gain access outside of the namespace.
([link moved to references], CVE-2015-8709)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-74-generic", ver:"3.13.0-74.118", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-74-generic-lpae", ver:"3.13.0-74.118", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-74-lowlatency", ver:"3.13.0-74.118", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-74-powerpc-e500", ver:"3.13.0-74.118", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-74-powerpc-e500mc", ver:"3.13.0-74.118", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-74-powerpc-smp", ver:"3.13.0-74.118", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-74-powerpc64-emb", ver:"3.13.0-74.118", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-74-powerpc64-smp", ver:"3.13.0-74.118", rls:"UBUNTU14.04 LTS"))) {
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
