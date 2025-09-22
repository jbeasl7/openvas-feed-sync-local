# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7348.2");
  script_cve_id("CVE-2025-0938");
  script_tag(name:"creation_date", value:"2025-03-25 04:04:19 +0000 (Tue, 25 Mar 2025)");
  script_version("2025-03-25T05:38:56+0000");
  script_tag(name:"last_modification", value:"2025-03-25 05:38:56 +0000 (Tue, 25 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7348-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7348-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7348-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.5, python3.8' package(s) announced via the USN-7348-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7348-1 fixed vulnerabilities in Python. The update introduced a
regression. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the Python ipaddress module contained incorrect
 information about which IP address ranges were considered 'private' or
 'globally reachable'. This could possibly result in applications applying
 incorrect security policies. This issue only affected Ubuntu 14.04 LTS
 and Ubuntu 16.04 LTS. (CVE-2024-4032)

 It was discovered that Python incorrectly handled quoting path names when
 using the venv module. A local attacker able to control virtual
 environments could possibly use this issue to execute arbitrary code when
 the virtual environment is activated. (CVE-2024-9287)

 It was discovered that Python incorrectly handled parsing bracketed hosts.
 A remote attacker could possibly use this issue to perform a Server-Side
 Request Forgery (SSRF) attack. This issue only affected Ubuntu 14.04 LTS
 and Ubuntu 16.04 LTS. (CVE-2024-11168)

 It was discovered that Python incorrectly handled parsing domain names that
 included square brackets. A remote attacker could possibly use this issue
 to perform a Server-Side Request Forgery (SSRF) attack. (CVE-2025-0938)");

  script_tag(name:"affected", value:"'python3.5, python3.8' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3.5", ver:"3.5.2-2ubuntu0~16.04.4~14.04.1+esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.5-minimal", ver:"3.5.2-2ubuntu0~16.04.4~14.04.1+esm6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.5-venv", ver:"3.5.2-2ubuntu0~16.04.4~14.04.1+esm6", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.5", ver:"3.5.2-2ubuntu0~16.04.13+esm18", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.5-minimal", ver:"3.5.2-2ubuntu0~16.04.13+esm18", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.5-venv", ver:"3.5.2-2ubuntu0~16.04.13+esm18", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.8", ver:"3.8.10-0ubuntu1~20.04.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8-minimal", ver:"3.8.10-0ubuntu1~20.04.18", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8-venv", ver:"3.8.10-0ubuntu1~20.04.18", rls:"UBUNTU20.04 LTS"))) {
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
