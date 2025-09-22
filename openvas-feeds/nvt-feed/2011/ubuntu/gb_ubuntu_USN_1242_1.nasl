# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840789");
  script_cve_id("CVE-2011-1479", "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2695", "CVE-2011-2905", "CVE-2011-2909", "CVE-2011-3188", "CVE-2011-3363");
  script_tag(name:"creation_date", value:"2011-10-31 12:45:00 +0000 (Mon, 31 Oct 2011)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-05-25 17:34:00 +0000 (Fri, 25 May 2012)");

  script_name("Ubuntu: Security Advisory (USN-1242-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1242-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1242-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-backport-maverick' package(s) announced via the USN-1242-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the security fix for CVE-2010-4250 introduced a
regression. A remote attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-1479)

Vasiliy Kulikov discovered that taskstats did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2494)

Vasiliy Kulikov discovered that /proc/PID/io did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2495)

It was discovered that the EXT4 filesystem contained multiple off-by-one
flaws. A local attacker could exploit this to crash the system, leading to
a denial of service. (CVE-2011-2695)

Christian Ohm discovered that the perf command looks for configuration
files in the current directory. If a privileged user were tricked into
running perf in a directory containing a malicious configuration file, an
attacker could run arbitrary commands and possibly gain privileges.
(CVE-2011-2905)

Vasiliy Kulikov discovered that the Comedi driver did not correctly clear
memory. A local attacker could exploit this to read kernel stack memory,
leading to a loss of privacy. (CVE-2011-2909)

Dan Kaminsky discovered that the kernel incorrectly handled random sequence
number generation. An attacker could use this flaw to possibly predict
sequence numbers and inject packets. (CVE-2011-3188)

Yogesh Sharma discovered that CIFS did not correctly handle UNCs that had
no prefixpaths. A local attacker with access to a CIFS partition could
exploit this to crash the system, leading to a denial of service.
(CVE-2011-3363)");

  script_tag(name:"affected", value:"'linux-lts-backport-maverick' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic", ver:"2.6.35-30.61~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-generic-pae", ver:"2.6.35-30.61~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-server", ver:"2.6.35-30.61~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.35-30-virtual", ver:"2.6.35-30.61~lucid1", rls:"UBUNTU10.04 LTS"))) {
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
