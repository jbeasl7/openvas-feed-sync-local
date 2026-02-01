# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7985.1");
  script_cve_id("CVE-2022-24106", "CVE-2022-24107", "CVE-2023-32668", "CVE-2024-25262");
  script_tag(name:"creation_date", value:"2026-01-30 04:33:13 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-01 20:40:02 +0000 (Thu, 01 Sep 2022)");

  script_name("Ubuntu: Security Advisory (USN-7985-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7985-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7985-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'texlive-bin' package(s) announced via the USN-7985-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Shin Ando discovered that the Xpdf toolkit embedded in TeX Live incorrectly
handled memory when decoding certain data streams. An attacker could
possibly use this issue to cause TeX Live to crash, resulting in a denial
of service, or execute arbitrary code. This issue only affected Ubuntu
20.04 LTS and Ubuntu 22.04 LTS. (CVE-2022-24106, CVE-2022-24107)

It was discovered that TeX Live allowed documents to make arbitrary network
requests. If a user or automated system were tricked into opening a
specially crafted document, a remote attacker could possibly use this issue
to exfiltrate sensitive information, or perform other network-related
attacks. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2023-32668)

It was discovered that TeX Live incorrectly handled certain TrueType fonts.
If a user or automated system were tricked into opening a specially crafted
TrueType font, a remote attacker could use this issue to cause TeX Live to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2024-25262)");

  script_tag(name:"affected", value:"'texlive-bin' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"texlive-binaries", ver:"2015.20160222.37495-1ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"texlive-binaries", ver:"2017.20170613.44572-8ubuntu0.2+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"texlive-binaries", ver:"2019.20190605.51237-3ubuntu0.2+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"texlive-binaries", ver:"2021.20210626.59705-1ubuntu0.3", rls:"UBUNTU22.04 LTS"))) {
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
