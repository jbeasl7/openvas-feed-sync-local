# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6842.1");
  script_cve_id("CVE-2022-4285", "CVE-2023-1972", "CVE-2023-39128", "CVE-2023-39129", "CVE-2023-39130");
  script_tag(name:"creation_date", value:"2024-06-21 04:07:54 +0000 (Fri, 21 Jun 2024)");
  script_version("2024-06-21T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-25 17:26:20 +0000 (Thu, 25 May 2023)");

  script_name("Ubuntu: Security Advisory (USN-6842-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6842-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6842-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb' package(s) announced via the USN-6842-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that gdb incorrectly handled certain memory operations
when parsing an ELF file. An attacker could possibly use this issue
to cause a denial of service. This issue is the result of an
incomplete fix for CVE-2020-16599. This issue only affected
Ubuntu 22.04 LTS. (CVE-2022-4285)

It was discovered that gdb incorrectly handled memory leading
to a heap based buffer overflow. An attacker could use this
issue to cause a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 22.04 LTS.
(CVE-2023-1972)

It was discovered that gdb incorrectly handled memory leading
to a stack overflow. An attacker could possibly use this issue
to cause a denial of service. This issue only affected
Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2023-39128)

It was discovered that gdb had a use after free vulnerability
under certain circumstances. An attacker could use this to cause
a denial of service or possibly execute arbitrary code. This issue
only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS
and Ubuntu 22.04 LTS. (CVE-2023-39129)

It was discovered that gdb incorrectly handled memory leading to a
heap based buffer overflow. An attacker could use this issue to cause
a denial of service, or possibly execute arbitrary code. This issue
only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2023-39130)");

  script_tag(name:"affected", value:"'gdb' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gdb", ver:"7.11.1-0ubuntu1~16.5+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gdbserver", ver:"7.11.1-0ubuntu1~16.5+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gdb", ver:"8.1.1-0ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gdbserver", ver:"8.1.1-0ubuntu1+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gdb", ver:"9.2-0ubuntu1~20.04.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gdbserver", ver:"9.2-0ubuntu1~20.04.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gdb", ver:"12.1-0ubuntu1~22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gdbserver", ver:"12.1-0ubuntu1~22.04.2", rls:"UBUNTU22.04 LTS"))) {
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
