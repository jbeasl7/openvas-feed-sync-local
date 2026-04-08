# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8147.1");
  script_cve_id("CVE-2019-19221", "CVE-2024-20696", "CVE-2025-25724", "CVE-2025-5914", "CVE-2025-5916", "CVE-2025-5917", "CVE-2025-5918", "CVE-2025-60753", "CVE-2026-4111");
  script_tag(name:"creation_date", value:"2026-04-07 04:48:28 +0000 (Tue, 07 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-07 16:15:50 +0000 (Wed, 07 Jan 2026)");

  script_name("Ubuntu: Security Advisory (USN-8147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8147-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8147-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the USN-8147-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libarchive incorrectly handled certain archive
files. An attacker could possibly use this issue to access sensitive
information. This issue only affected Ubuntu 14.04 LTS. (CVE-2019-19221)

It was discovered that libarchive incorrectly handled certain RAR archive
files. If a user or automated system were tricked into processing a
specially crafted RAR archive, an attacker could possibly use this issue to
cause libarchive to crash, resulting in a denial of service, or execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS
and Ubuntu 18.04 LTS. (CVE-2024-20696)

It was discovered that libarchive incorrectly handled certain RAR archive
files. An attacker could possibly use this issue to execute arbitrary code
or cause a denial of service. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2025-5914)

It was discovered that libarchive incorrectly handled certain WARC archive
files. If a user or automated system were tricked into processing a
specially crafted WARC archive, an attacker could possibly use this issue
to cause libarchive to crash, resulting in a denial of service. This issue
only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2025-5916)

It was discovered that libarchive incorrectly handled certain file names
when handling prefixes and suffixes. An attacker could possibly use this
issue to cause libarchive to crash, resulting in a denial of service. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS
and Ubuntu 20.04 LTS. (CVE-2025-5917)

It was discovered that libarchive could read past the end of file streams
when processing input to bsdtar. An attacker could possibly use this issue
to cause memory corruption or a denial of service. (CVE-2025-5918)

It was discovered that libarchive incorrectly handled certain TAR archive
files. If a user or automated system were tricked into processing a
specially crafted TAR archive, an attacker could possibly use this issue to
cause libarchive to crash, resulting in a denial of service, or execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS
and Ubuntu 18.04 LTS. (CVE-2025-25724)

HyungJung Joo discovered that libarchive did not properly limit memory
allocation when processing substitution rules in bsdtar. An attacker could
possibly use this issue to cause excessive memory consumption, leading to a
denial of service. (CVE-2025-60753)

Elhanan Haenel discovered that libarchive could enter an infinite loop when
processing crafted RAR5 archives. An attacker could possibly use this issue
to cause excessive CPU consumption, leading to a denial of service. This
issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS
and Ubuntu 25.10. (CVE-2026-4111)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bsdcpio", ver:"3.1.2-7ubuntu2.8+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bsdtar", ver:"3.1.2-7ubuntu2.8+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"3.1.2-7ubuntu2.8+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13", ver:"3.1.2-7ubuntu2.8+esm4", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"bsdcpio", ver:"3.1.2-11ubuntu0.16.04.8+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bsdtar", ver:"3.1.2-11ubuntu0.16.04.8+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"3.1.2-11ubuntu0.16.04.8+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13", ver:"3.1.2-11ubuntu0.16.04.8+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"bsdcpio", ver:"3.2.2-3.1ubuntu0.7+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bsdtar", ver:"3.2.2-3.1ubuntu0.7+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"3.2.2-3.1ubuntu0.7+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-tools", ver:"3.2.2-3.1ubuntu0.7+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13", ver:"3.2.2-3.1ubuntu0.7+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"3.4.0-2ubuntu1.5+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-tools", ver:"3.4.0-2ubuntu1.5+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13", ver:"3.4.0-2ubuntu1.5+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"3.6.0-1ubuntu1.6", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-tools", ver:"3.6.0-1ubuntu1.6", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13", ver:"3.6.0-1ubuntu1.6", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"3.7.2-2ubuntu0.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-tools", ver:"3.7.2-2ubuntu0.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13t64", ver:"3.7.2-2ubuntu0.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"3.7.7-0ubuntu3.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive-tools", ver:"3.7.7-0ubuntu3.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13t64", ver:"3.7.7-0ubuntu3.1", rls:"UBUNTU25.10"))) {
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
