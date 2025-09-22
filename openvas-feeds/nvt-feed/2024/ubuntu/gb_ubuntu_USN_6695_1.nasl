# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6695.1");
  script_cve_id("CVE-2019-18604", "CVE-2023-32668", "CVE-2024-25262");
  script_tag(name:"creation_date", value:"2024-03-15 04:09:20 +0000 (Fri, 15 Mar 2024)");
  script_version("2024-03-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2024-03-15 05:06:15 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-05 17:48:24 +0000 (Tue, 05 Nov 2019)");

  script_name("Ubuntu: Security Advisory (USN-6695-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6695-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6695-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'texlive-bin' package(s) announced via the USN-6695-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that TeX Live incorrectly handled certain memory
operations in the embedded axodraw2 tool. An attacker could possibly use
this issue to cause TeX Live to crash, resulting in a denial of service.
This issue only affected Ubuntu 20.04 LTS. (CVE-2019-18604)

It was discovered that TeX Live allowed documents to make arbitrary
network requests. If a user or automated system were tricked into opening a
specially crafted document, a remote attacker could possibly use this issue
to exfiltrate sensitive information, or perform other network-related
attacks. This issue only affected Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS.
(CVE-2023-32668)

It was discovered that TeX Live incorrectly handled certain TrueType fonts.
If a user or automated system were tricked into opening a specially crafted
TrueType font, a remote attacker could use this issue to cause TeX Live to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2024-25262)");

  script_tag(name:"affected", value:"'texlive-bin' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"texlive-binaries", ver:"2019.20190605.51237-3ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"texlive-binaries", ver:"2021.20210626.59705-1ubuntu0.2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"texlive-binaries", ver:"2023.20230311.66589-6ubuntu0.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texlive-binaries-sse2", ver:"2023.20230311.66589-6ubuntu0.1", rls:"UBUNTU23.10"))) {
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
