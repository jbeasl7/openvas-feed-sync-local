# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840838");
  script_cve_id("CVE-2011-1162", "CVE-2011-3638", "CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4326", "CVE-2011-4330");
  script_tag(name:"creation_date", value:"2011-12-16 05:41:34 +0000 (Fri, 16 Dec 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-05-25 20:16:00 +0000 (Fri, 25 May 2012)");

  script_name("Ubuntu: Security Advisory (USN-1299-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1299-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1299-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-1299-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter Huewe discovered an information leak in the handling of reading
security-related TPM data. A local, unprivileged user could read the
results of a previous TPM command. (CVE-2011-1162)

Zheng Liu discovered a flaw in how the ext4 filesystem splits extents. A
local unprivileged attacker could exploit this to crash the system, leading
to a denial of service. (CVE-2011-3638)

A bug was discovered in the XFS filesystem's handling of pathnames. A local
attacker could exploit this to crash the system, leading to a denial of
service, or gain root privileges. (CVE-2011-4077)

Nick Bowler discovered the kernel GHASH message digest algorithm
incorrectly handled error conditions. A local attacker could exploit this
to cause a kernel oops. (CVE-2011-4081)

A flaw was found in the Journaling Block Device (JBD). A local attacker
able to mount ext3 or ext4 file systems could exploit this to crash the
system, leading to a denial of service. (CVE-2011-4132)

A bug was found in the way headroom check was performed in
udp6_ufo_fragment() function. A remote attacker could use this flaw to
crash the system. (CVE-2011-4326)

Clement Lecigne discovered a bug in the HFS file system bounds checking.
When a malformed HFS file system is mounted a local user could crash the
system or gain root privileges. (CVE-2011-4330)");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-341-ec2", ver:"2.6.32-341.42", rls:"UBUNTU10.04 LTS"))) {
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
