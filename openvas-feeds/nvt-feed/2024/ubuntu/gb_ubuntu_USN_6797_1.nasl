# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6797.1");
  script_cve_id("CVE-2023-22655", "CVE-2023-28746", "CVE-2023-38575", "CVE-2023-39368", "CVE-2023-43490", "CVE-2023-45733", "CVE-2023-45745", "CVE-2023-46103", "CVE-2023-47855");
  script_tag(name:"creation_date", value:"2024-05-30 04:08:53 +0000 (Thu, 30 May 2024)");
  script_version("2024-05-30T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-30 05:05:32 +0000 (Thu, 30 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6797-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.10|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6797-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6797-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode' package(s) announced via the USN-6797-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that some 3rd and 4th Generation Intel(r) Xeon(r) Processors
did not properly restrict access to certain hardware features when using
Intel(r) SGX or Intel(r) TDX. This may allow a privileged local user to
potentially further escalate their privileges on the system. This issue only
affected Ubuntu 23.10, Ubuntu 22.04 LTS, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS and
Ubuntu 16.04 LTS. (CVE-2023-22655)

It was discovered that some Intel(r) Atom(r) Processors did not properly clear
register state when performing various operations. A local attacker could
use this to obtain sensitive information via a transient execution attack.
This issue only affected Ubuntu 23.10, Ubuntu 22.04 LTS, Ubuntu 20.04 LTS,
Ubuntu 18.04 LTS and Ubuntu 16.04 LTS. (CVE-2023-28746)

It was discovered that some Intel(r) Processors did not properly clear the
state of various hardware structures when switching execution contexts. A
local attacker could use this to access privileged information. This issue only
affected Ubuntu 23.10, Ubuntu 22.04 LTS, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS and
Ubuntu 16.04 LTS. (CVE-2023-38575)

It was discovered that some Intel(r) Processors did not properly enforce bus
lock regulator protections. A remote attacker could use this to cause a
denial of service. This issue only affected Ubuntu 23.10, Ubuntu 22.04 LTS,
Ubuntu 20.04 LTS, Ubuntu 18.04 LTS and Ubuntu 16.04 LTS. (CVE-2023-39368)

It was discovered that some Intel(r) Xeon(r) D Processors did not properly
calculate the SGX base key when using Intel(r) SGX. A privileged local
attacker could use this to obtain sensitive information. This issue only
affected Ubuntu 23.10, Ubuntu 22.04 LTS, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS and
Ubuntu 16.04 LTS. (CVE-2023-43490)

It was discovered that some Intel(r) Processors did not properly protect against
concurrent accesses. A local attacker could use this to obtain sensitive
information. (CVE-2023-45733)

It was discovered that some Intel(r) Processors TDX module software did not
properly validate input. A privileged local attacker could use this information
to potentially further escalate their privileges on the system.
(CVE-2023-45745, CVE-2023-47855)

It was discovered that some Intel(r) Core(tm) Ultra processors did not properly
handle particular instruction sequences. A local attacker could use this
issue to cause a denial of service. (CVE-2023-46103)");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20240514.0ubuntu0.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20240514.0ubuntu0.18.04.1+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20240514.0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20240514.0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20240514.0ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20240514.0ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
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
