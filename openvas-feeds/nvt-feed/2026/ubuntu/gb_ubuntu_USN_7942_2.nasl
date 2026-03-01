# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7942.2");
  script_cve_id("CVE-2025-13601", "CVE-2025-14087", "CVE-2025-3360", "CVE-2025-7039");
  script_tag(name:"creation_date", value:"2026-02-12 11:19:52 +0000 (Thu, 12 Feb 2026)");
  script_version("2026-02-13T05:57:48+0000");
  script_tag(name:"last_modification", value:"2026-02-13 05:57:48 +0000 (Fri, 13 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-06 17:19:39 +0000 (Fri, 06 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-7942-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7942-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7942-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2.0' package(s) announced via the USN-7942-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7942-1 fixed vulnerabilities in GLib. This update provides the
corresponding updates for Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04
LTS, and Ubuntu 20.04 LTS. CVE-2025-3360 only affected Ubuntu 18.04
LTS and Ubuntu 20.04 LTS.

Original advisory details:

 It was discovered that GLib incorrectly handled escaping URI strings. An
 attacker could use this issue to cause GLib to crash, resulting in a
 denial of service, or possibly execute arbitrary code. (CVE-2025-13601)

 It was discovered that GLib incorrectly parsed certain GVariants. An
 attacker could use this issue to cause GLib to crash, resulting in a
 denial of service, or possibly execute arbitrary code. (CVE-2025-14087)

 It was discovered that GLib incorrectly parsed certain long invalid ISO
 8601 timestamps. An attacker could possibly use this issue to cause GLib
 to crash, resulting in a denial of service. This issue only affected
 Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2025-3360)

 It was discovered that GLib incorrectly handled GString memory operations.
 An attacker could use this issue to cause GLib to crash, resulting in a
 denial of service, or possibly execute arbitrary code. This issue only
 affected Ubuntu 24.04 LTS and Ubuntu 25.04. (CVE-2025-6052)

 It was discovered that GLib incorrectly handled creating temporary files.
 An attacker could possibly use this issue to access unauthorized data.
 This issue only affected Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu
 25.04. (CVE-2025-7039)");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.40.2-0ubuntu1.1+esm7", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.48.2-0ubuntu4.8+esm5", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.56.4-0ubuntu0.18.04.9+esm5", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.64.6-1~ubuntu20.04.9+esm1", rls:"UBUNTU20.04 LTS"))) {
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
