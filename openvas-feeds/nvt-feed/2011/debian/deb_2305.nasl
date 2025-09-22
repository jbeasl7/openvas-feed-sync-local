# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70399");
  script_cve_id("CVE-2011-0762");
  script_tag(name:"creation_date", value:"2011-10-16 21:01:53 +0000 (Sun, 16 Oct 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2305-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2305-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2305-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2305");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vsftpd' package(s) announced via the DSA-2305-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issue have been discovered that affect vsftpd, a lightweight, efficient FTP server written for security.

CVE-2011-2189

It was discovered that Linux kernels < 2.6.35 are considerably slower in releasing than in the creation of network namespaces. As a result of this and because vsftpd is using this feature as a security enhancement to provide network isolation for connections, it is possible to cause denial of service conditions due to excessive memory allocations by the kernel. This is technically no vsftpd flaw, but a kernel issue. However, this feature has legitimate use cases and backporting the specific kernel patch is too intrusive. Additionally, a local attacker requires the CAP_SYS_ADMIN capability to abuse this functionality. Therefore, as a fix, a kernel version check has been added to vsftpd in order to disable this feature for kernels < 2.6.35.

CVE-2011-0762

Maksymilian Arciemowicz discovered that vsftpd is incorrectly handling certain glob expressions in STAT commands. This allows a remote authenticated attacker to conduct denial of service attacks (excessive CPU and process slot exhaustion) via crafted STAT commands.

For the oldstable distribution (lenny), this problem has been fixed in version 2.0.7-1+lenny1.

For the stable distribution (squeeze), this problem has been fixed in version 2.3.2-3+squeeze2. Please note that CVE-2011-2189 does not affect the lenny version.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 2.3.4-1.

We recommend that you upgrade your vsftpd packages.");

  script_tag(name:"affected", value:"'vsftpd' package(s) on Debian 5, Debian 6.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"vsftpd", ver:"2.0.7-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"vsftpd", ver:"2.3.2-3+squeeze2", rls:"DEB6"))) {
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
