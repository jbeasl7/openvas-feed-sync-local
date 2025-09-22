# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7422.1");
  script_cve_id("CVE-2021-44492", "CVE-2021-44498", "CVE-2021-44500", "CVE-2021-44502", "CVE-2021-44506", "CVE-2021-44508", "CVE-2021-44509", "CVE-2021-44510");
  script_tag(name:"creation_date", value:"2025-04-08 04:04:14 +0000 (Tue, 08 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 15:30:29 +0000 (Fri, 22 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-7422-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7422-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7422-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fis-gtm' package(s) announced via the USN-7422-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FIS-GT.M could incorrectly dereference memory in
certain instances. An attacker could possibly use this issue to cause
FIS-GT.M to crash, resulting in a denial of service.
(CVE-2021-44492, CVE-2021-44498, CVE-2021-44508)

It was discovered that FIS-GT.M could perform a division by zero due to
a lack of input validation. An attacker could possibly use this issue to
cause FIS-GT.M to crash, resulting in a denial of service.
(CVE-2021-44500)

It was discovered that FIS-GT.M could be forced to allocate memory of a
chosen size through crafted input. An attacker could possibly use this
issue to exhaust the available memory of FIS-GT.M, leading to a crash
that would result in a denial of service. (CVE-2021-44502)

It was discovered that FIS-GT.M could be forced to read from uninitialized
memory due to a lack of input validation. An attacker could possibly use
this issue to cause FIS-GT.M to crash, resulting in a denial of service,
or execute arbitrary code. (CVE-2021-44506)

It was discovered that FIS-GT.M could crash due to an integer underflow.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2021-44509, CVE-2021-44510)");

  script_tag(name:"affected", value:"'fis-gtm' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"fis-gtm", ver:"6.2-002A-2ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fis-gtm-6.2-002", ver:"6.2-002A-2ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"fis-gtm", ver:"6.3-003A-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fis-gtm-6.3-003a", ver:"6.3-003A-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"fis-gtm", ver:"6.3-007-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fis-gtm-6.3-007", ver:"6.3-007-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"fis-gtm", ver:"6.3-014-3ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fis-gtm-6.3-014", ver:"6.3-014-3ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
