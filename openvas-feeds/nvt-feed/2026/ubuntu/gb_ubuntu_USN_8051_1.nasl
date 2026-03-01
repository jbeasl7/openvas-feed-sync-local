# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8051.1");
  script_cve_id("CVE-2025-8277", "CVE-2026-0964", "CVE-2026-0965", "CVE-2026-0966", "CVE-2026-0967", "CVE-2026-0968");
  script_tag(name:"creation_date", value:"2026-02-20 04:34:42 +0000 (Fri, 20 Feb 2026)");
  script_version("2026-02-20T05:55:45+0000");
  script_tag(name:"last_modification", value:"2026-02-20 05:55:45 +0000 (Fri, 20 Feb 2026)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-09 12:15:30 +0000 (Tue, 09 Sep 2025)");

  script_name("Ubuntu: Security Advisory (USN-8051-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8051-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8051-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the USN-8051-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libssh clients incorrectly handled the key exchange
process. A remote attacker could possibly use this issue to cause libssh
clients to crash, resulting in a denial of service. (CVE-2025-8277)

It was discovered that the libssh SCP client incorrectly sanitized paths
received from servers. A remote attacker could use this issue to cause
libssh SCP clients to overwrite files outside of the working directory and
possibly execute arbitrary code. (CVE-2026-0964)

It was discovered that libssh incorrectly handled parsing configuration
files. A local attacker could possibly use this issue to cause libssh to
access non-regular files, resulting in a denial of service. (CVE-2026-0965)

It was discovered that libssh incorrectly handled the ssh_get_hexa()
function. A remote attacker could possibly use this issue to cause libssh
to crash, resulting in a denial of service. (CVE-2026-0966)

It was discovered that libssh incorrectly handled certain regular
expressions. A local attacker could possibly use this issue to cause libssh
to consume resources, resulting in a denial of service. (CVE-2026-0967)

It was discovered that the libssh SFTP client incorrectly handled certain
malformed longname fields. A remote attacker could use this issue to cause
libssh SFTP clients to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2026-0968)");

  script_tag(name:"affected", value:"'libssh' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssh-4", ver:"0.9.6-2ubuntu0.22.04.6", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssh-4", ver:"0.10.6-2ubuntu0.3", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssh-4", ver:"0.11.2-1ubuntu0.2", rls:"UBUNTU25.10"))) {
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
