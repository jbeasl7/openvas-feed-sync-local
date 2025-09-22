# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6940.1");
  script_cve_id("CVE-2024-1724", "CVE-2024-29068", "CVE-2024-29069");
  script_tag(name:"creation_date", value:"2024-08-02 04:08:24 +0000 (Fri, 02 Aug 2024)");
  script_version("2024-08-27T05:05:50+0000");
  script_tag(name:"last_modification", value:"2024-08-27 05:05:50 +0000 (Tue, 27 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-26 16:44:59 +0000 (Mon, 26 Aug 2024)");

  script_name("Ubuntu: Security Advisory (USN-6940-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6940-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6940-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'snapd' package(s) announced via the USN-6940-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Neil McPhail discovered that snapd did not properly restrict writes to the
$HOME/bin path in the AppArmor profile for snaps using the home plug. An
attacker who could convince a user to install a malicious snap could use this
vulnerability to escape the snap sandbox. (CVE-2024-1724)

Zeyad Gouda discovered that snapd failed to properly check the file type when
extracting a snap. An attacker who could convince a user to install a malicious
snap containing non-regular files could then cause snapd to block indefinitely
while trying to read from such files and cause a denial of
service. (CVE-2024-29068)

Zeyad Gouda discovered that snapd failed to properly check the destination of
symbolic links when extracting a snap. An attacker who could convince a user to
install a malicious snap containing crafted symbolic links could then cause
snapd to write out the contents of the symbolic link destination into a
world-readable directory. This in-turn could allow a local unprivileged user to
gain access to privileged information. (CVE-2024-29069)");

  script_tag(name:"affected", value:"'snapd' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"snapd", ver:"2.63+20.04ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"snapd", ver:"2.63+22.04ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"snapd", ver:"2.63+24.04ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
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
