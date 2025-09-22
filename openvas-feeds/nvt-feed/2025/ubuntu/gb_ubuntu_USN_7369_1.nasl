# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7369.1");
  script_cve_id("CVE-2024-25260", "CVE-2025-1365", "CVE-2025-1371", "CVE-2025-1372", "CVE-2025-1377");
  script_tag(name:"creation_date", value:"2025-03-25 04:04:19 +0000 (Tue, 25 Mar 2025)");
  script_version("2025-03-25T05:38:56+0000");
  script_tag(name:"last_modification", value:"2025-03-25 05:38:56 +0000 (Tue, 25 Mar 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-17 03:15:09 +0000 (Mon, 17 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-7369-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7369-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7369-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils' package(s) announced via the USN-7369-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that readelf from elfutils could be made to read out of
bounds. If a user or automated system were tricked into running readelf
on a specially crafted file, an attacker could cause readelf to crash,
resulting in a denial of service. This issue only affected Ubuntu 24.04
LTS. (CVE-2024-25260)

It was discovered that readelf from elfutils could be made to write out of
bounds. If a user or automated system were tricked into running readelf
on a specially crafted file, an attacker could cause readelf to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only affected Ubuntu 24.04 LTS and Ubuntu 24.10. (CVE-2025-1365)

It was discovered that readelf from elfutils could be made to dereference
invalid memory. If a user or automated system were tricked into running
readelf on a specially crafted file, an attacker could cause readelf to
crash, resulting in a denial of service. This issue only affected Ubuntu
24.04 LTS and Ubuntu 24.10. (CVE-2025-1371)

It was discovered that readelf from elfutils could be made to dereference
invalid memory. If a user or automated system were tricked into running
readelf on a specially crafted file, an attacker could cause readelf to
crash, resulting in a denial of service. (CVE-2025-1372)

It was discovered that strip from elfutils could be made to dereference
invalid memory. If a user or automated system were tricked into running
strip on a specially crafted file, an attacker could cause strip to
crash, resulting in a denial of service. (CVE-2025-1377)");

  script_tag(name:"affected", value:"'elfutils' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"elfutils", ver:"0.186-1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"elfutils", ver:"0.190-1.1ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"elfutils", ver:"0.191-2ubuntu0.1", rls:"UBUNTU24.10"))) {
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
