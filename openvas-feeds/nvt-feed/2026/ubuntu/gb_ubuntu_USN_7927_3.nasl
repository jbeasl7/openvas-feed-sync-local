# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7927.3");
  script_cve_id("CVE-2025-66471");
  script_tag(name:"creation_date", value:"2026-01-15 04:19:36 +0000 (Thu, 15 Jan 2026)");
  script_version("2026-01-15T05:47:46+0000");
  script_tag(name:"last_modification", value:"2026-01-15 05:47:46 +0000 (Thu, 15 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-10 16:10:33 +0000 (Wed, 10 Dec 2025)");

  script_name("Ubuntu: Security Advisory (USN-7927-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7927-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7927-3");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/bugs/2136906");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-urllib3' package(s) announced via the USN-7927-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7927-1 fixed vulnerabilities in urllib3. The update for CVE-2025-66471
introduced a regression in urllib3 when decompressing zstd data. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Illia Volochii discovered that urllib3 did not limit the steps in a
 decompression chain. An attacker could possibly use this issue to cause
 urllib3 to use excessive resources, causing a denial of service.
 (CVE-2025-66418)

 Rui Xi discovered that urllib3 incorrectly handled highly compressed data.
 An attacker could possibly use this issue to cause urllib3 to use
 excessive resources, causing a denial of service. This issue only affected
 Ubuntu 24.04 LTS, Ubuntu 25.04, and Ubuntu 25.10. (CVE-2025-66471)

 For the brotli encoding, the fix for CVE-2025-66471 requires an additional
 security update in the brotli package.");

  script_tag(name:"affected", value:"'python-urllib3' package(s) on Ubuntu 24.04, Ubuntu 25.04, Ubuntu 25.10.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python3-urllib3", ver:"2.0.7-1ubuntu0.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"python3-urllib3", ver:"2.3.0-2ubuntu0.5", rls:"UBUNTU25.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-urllib3", ver:"2.3.0-3ubuntu0.4", rls:"UBUNTU25.10"))) {
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
