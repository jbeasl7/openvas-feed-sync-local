# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6920.1");
  script_cve_id("CVE-2017-5731", "CVE-2018-12182", "CVE-2018-12183", "CVE-2018-3613", "CVE-2019-0160");
  script_tag(name:"creation_date", value:"2024-07-30 04:08:39 +0000 (Tue, 30 Jul 2024)");
  script_version("2024-07-30T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-07-30 05:05:46 +0000 (Tue, 30 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-28 15:25:14 +0000 (Thu, 28 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-6920-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6920-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6920-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2' package(s) announced via the USN-6920-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that EDK II was not properly performing bounds checks
in Tianocompress, which could lead to a buffer overflow. An authenticated
user could use this issue to potentially escalate their privileges via
local access. (CVE-2017-5731)

It was discovered that EDK II had an insufficient memory write check in
the SMM service, which could lead to a page fault occurring. An
authenticated user could use this issue to potentially escalate their
privileges, disclose information and/or create a denial of service via
local access. (CVE-2018-12182)

It was discovered that EDK II incorrectly handled memory in DxeCore, which
could lead to a stack overflow. An unauthenticated user could this
issue to potentially escalate their privileges, disclose information
and/or create a denial of service via local access. This issue only
affected Ubuntu 18.04 LTS. (CVE-2018-12183)

It was discovered that EDK II incorrectly handled memory in the
Variable service under certain circumstances. An authenticated user could
use this issue to potentially escalate their privileges, disclose
information and/or create a denial of service via local access.
(CVE-2018-3613)

It was discovered that EDK II incorrectly handled memory in its system
firmware, which could lead to a buffer overflow. An unauthenticated user
could use this issue to potentially escalate their privileges and/or
create a denial of service via network access. This issue only affected
Ubuntu 18.04 LTS. (CVE-2019-0160)");

  script_tag(name:"affected", value:"'edk2' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20160408.ffea0a2c-2ubuntu0.2+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi", ver:"0~20160408.ffea0a2c-2ubuntu0.2+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"0~20180205.c0d9813c-2ubuntu0.3+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi", ver:"0~20180205.c0d9813c-2ubuntu0.3+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"0~20180205.c0d9813c-2ubuntu0.3+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"0~20180205.c0d9813c-2ubuntu0.3+esm1", rls:"UBUNTU18.04 LTS"))) {
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
