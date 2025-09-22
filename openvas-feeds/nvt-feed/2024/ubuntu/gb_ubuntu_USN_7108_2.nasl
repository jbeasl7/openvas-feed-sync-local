# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7108.2");
  script_cve_id("CVE-2023-46445", "CVE-2023-46446");
  script_tag(name:"creation_date", value:"2024-12-13 04:08:23 +0000 (Fri, 13 Dec 2024)");
  script_version("2024-12-13T15:40:54+0000");
  script_tag(name:"last_modification", value:"2024-12-13 15:40:54 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-18 03:26:58 +0000 (Sat, 18 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-7108-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7108-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7108-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-asyncssh' package(s) announced via the USN-7108-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7108-1 fixed vulnerabilities in AysncSSH. This update provides the
corresponding update for Ubuntu 18.04 LTS.

Original advisory details:

 Fabian Baumer, Marcus Brinkmann, and Jorg Schwenk discovered that AsyncSSH
 did not properly handle the extension info message. An attacker able to
 intercept communications could possibly use this issue to downgrade
 the algorithm used for client authentication. (CVE-2023-46445)

 Fabian Baumer, Marcus Brinkmann, and Jorg Schwenk discovered that AsyncSSH
 did not properly handle the user authentication request message. An
 attacker could possibly use this issue to control the remote end of an SSH
 client session via packet injection/removal and shell emulation.
 (CVE-2023-46446)");

  script_tag(name:"affected", value:"'python-asyncssh' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python3-asyncssh", ver:"1.11.1-1ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
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
