# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7444.1");
  script_cve_id("CVE-2022-39335", "CVE-2022-39374", "CVE-2023-32683", "CVE-2023-41335", "CVE-2023-42453", "CVE-2023-43796", "CVE-2024-31208", "CVE-2024-53863");
  script_tag(name:"creation_date", value:"2025-04-23 04:04:26 +0000 (Wed, 23 Apr 2025)");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-26 14:59:05 +0000 (Tue, 26 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-7444-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7444-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7444-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'matrix-synapse' package(s) announced via the USN-7444-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Synapse network policies could be bypassed via
specially crafted URLs. An attacker could possibly use this issue to
bypass authentication mechanisms. (CVE-2023-32683)

It was discovered that Synapse exposed cached device information. An
attacker could possibly use this issue to gain access to sensitive
information. (CVE-2023-43796)

It was discovered that Synapse could be tricked into rejecting state
changes in rooms. An attacker could possibly use this issue to cause
Synapse to stop functioning properly, resulting in a denial of service.
This issue was only fixed in Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2022-39374)

It was discovered that Synapse stored user credentials in a server's
database temporarily. An attacker could possibly use this issue to
gain access to sensitive information. This issue was only fixed in
Ubuntu 22.04 LTS. (CVE-2023-41335)

It was discovered that Synapse could incorrectly respond to server
authorization events. An attacker could possibly use this issue to
bypass authentication mechanisms. This issue was only fixed in Ubuntu
22.04 LTS. (CVE-2022-39335)

It was discovered that Synapse could be manipulated to mark messages
as read when they had not been viewed. An attacker could possibly use
this issue to perform repudiation-based attacks. This issue was only
fixed in Ubuntu 22.04 LTS. (CVE-2023-42453)

It was discovered that Synapse had several memory-related issues. An
attacker could possibly use this issue to cause Synapse to crash,
resulting in a denial of service. This issue was only fixed in Ubuntu
22.04 LTS. (CVE-2024-31208)

It was discovered that Synapse could run external tools due to a
unchecked thumbnail rendering routine. An attacker could possibly use
this issue to cause Synapse to crash, resulting in a denial of service,
or execute arbitrary code. This issue was only fixed in Ubuntu
22.04 LTS. (CVE-2024-53863)");

  script_tag(name:"affected", value:"'matrix-synapse' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"matrix-synapse", ver:"0.24.0+dfsg-1ubuntu0.1~esm4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"matrix-synapse", ver:"1.11.0-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"matrix-synapse", ver:"1.53.0-1ubuntu0.1~esm2", rls:"UBUNTU22.04 LTS"))) {
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
