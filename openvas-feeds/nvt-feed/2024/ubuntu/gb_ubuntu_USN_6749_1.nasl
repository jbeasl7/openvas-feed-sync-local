# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6749.1");
  script_cve_id("CVE-2024-22211", "CVE-2024-32039", "CVE-2024-32040", "CVE-2024-32041", "CVE-2024-32458", "CVE-2024-32459", "CVE-2024-32460");
  script_tag(name:"creation_date", value:"2024-04-25 04:09:16 +0000 (Thu, 25 Apr 2024)");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:58:52 +0000 (Tue, 04 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-6749-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6749-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6749-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp2' package(s) announced via the USN-6749-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FreeRDP incorrectly handled certain context resets.
If a user were tricked into connecting to a malicious server, a remote
attacker could use this issue to cause FreeRDP to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2024-22211)

Evgeny Legerov discovered that FreeRDP incorrectly handled certain memory
operations. If a user were tricked into connecting to a malicious server, a
remote attacker could use this issue to cause FreeRDP to crash, resulting
in a denial of service, or possibly execute arbitrary code.
(CVE-2024-32039, CVE-2024-32040)

Evgeny Legerov discovered that FreeRDP incorrectly handled certain memory
operations. If a user were tricked into connecting to a malicious server, a
remote attacker could possibly use this issue to cause FreeRDP to crash,
resulting in a denial of service. (CVE-2024-32041, CVE-2024-32458,
CVE-2024-32460)

Evgeny Legerov discovered that FreeRDP incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to cause
FreeRDP clients and servers to crash, resulting in a denial of service.
(CVE-2024-32459)");

  script_tag(name:"affected", value:"'freerdp2' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.6.1+dfsg1-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.6.1+dfsg1-3ubuntu2.6", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2", ver:"2.10.0+dfsg1-1.1ubuntu1.2", rls:"UBUNTU23.10"))) {
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
