# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6762.1");
  script_cve_id("CVE-2014-9984", "CVE-2015-20109", "CVE-2018-11236", "CVE-2021-3999", "CVE-2024-2961");
  script_tag(name:"creation_date", value:"2024-05-03 04:10:49 +0000 (Fri, 03 May 2024)");
  script_version("2024-05-03T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-05-03 05:05:25 +0000 (Fri, 03 May 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-18 16:29:00 +0000 (Fri, 18 May 2018)");

  script_name("Ubuntu: Security Advisory (USN-6762-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6762-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6762-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2063328");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc, glibc' package(s) announced via the USN-6762-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GNU C Library incorrectly handled netgroup requests.
An attacker could possibly use this issue to cause a crash or execute arbitrary code.
This issue only affected Ubuntu 14.04 LTS. (CVE-2014-9984)

It was discovered that GNU C Library might allow context-dependent
attackers to cause a denial of service. This issue only affected Ubuntu 14.04 LTS.
(CVE-2015-20109)

It was discovered that GNU C Library when processing very long pathname arguments to
the realpath function, could encounter an integer overflow on 32-bit
architectures, leading to a stack-based buffer overflow and, potentially,
arbitrary code execution. This issue only affected Ubuntu 14.04 LTS.
(CVE-2018-11236)

It was discovered that the GNU C library getcwd function incorrectly
handled buffers. An attacker could use this issue to cause the GNU C
Library to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS. (CVE-2021-3999)

Charles Fol discovered that the GNU C Library iconv feature incorrectly
handled certain input sequences. An attacker could use this issue to cause
the GNU C Library to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2024-2961)");

  script_tag(name:"affected", value:"'eglibc, glibc' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.19-0ubuntu6.15+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.23-0ubuntu11.3+esm6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.27-3ubuntu1.6+esm2", rls:"UBUNTU18.04 LTS"))) {
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
