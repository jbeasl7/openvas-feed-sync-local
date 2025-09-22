# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842493");
  script_cve_id("CVE-2015-5156", "CVE-2015-5697", "CVE-2015-6252", "CVE-2015-6937", "CVE-2015-7312");
  script_tag(name:"creation_date", value:"2015-10-21 05:11:52 +0000 (Wed, 21 Oct 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-2777-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2777-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2777-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-utopic' package(s) announced via the USN-2777-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that virtio networking in the Linux kernel did not handle
fragments correctly, leading to kernel memory corruption. A remote attacker
could use this to cause a denial of service (system crash) or possibly
execute code with administrative privileges. (CVE-2015-5156)

Benjamin Randazzo discovered an information leak in the md (multiple
device) driver when the bitmap_info.file is disabled. A local privileged
attacker could use this to obtain sensitive information from the kernel.
(CVE-2015-5697)

Marc-Andre Lureau discovered that the vhost driver did not properly
release the userspace provided log file descriptor. A privileged attacker
could use this to cause a denial of service (resource exhaustion).
(CVE-2015-6252)

It was discovered that the Reliable Datagram Sockets (RDS) implementation
in the Linux kernel did not verify sockets were properly bound before
attempting to send a message, which could cause a NULL pointer dereference.
An attacker could use this to cause a denial of service (system crash).
(CVE-2015-6937)

Ben Hutchings discovered that the Advanced Union Filesystem (aufs) for the
Linux kernel did not correctly handle references of memory mapped files
from an aufs mount. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code with
administrative privileges. (CVE-2015-7312)");

  script_tag(name:"affected", value:"'linux-lts-utopic' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-51-generic", ver:"3.16.0-51.69~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-51-generic-lpae", ver:"3.16.0-51.69~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-51-lowlatency", ver:"3.16.0-51.69~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-51-powerpc-e500mc", ver:"3.16.0-51.69~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-51-powerpc-smp", ver:"3.16.0-51.69~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-51-powerpc64-emb", ver:"3.16.0-51.69~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-51-powerpc64-smp", ver:"3.16.0-51.69~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
