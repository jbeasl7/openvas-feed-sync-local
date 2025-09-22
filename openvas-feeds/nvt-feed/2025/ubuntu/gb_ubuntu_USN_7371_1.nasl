# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7371.1");
  script_cve_id("CVE-2024-32458", "CVE-2024-32459", "CVE-2024-32659", "CVE-2024-32660");
  script_tag(name:"creation_date", value:"2025-03-26 07:45:40 +0000 (Wed, 26 Mar 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:42:16 +0000 (Tue, 04 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-7371-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7371-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7371-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp2' package(s) announced via the USN-7371-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Evgeny Legerov discovered that FreeRDP incorrectly handled certain memory
operations. If a user were tricked into connecting to a malicious server, a
remote attacker could possibly use this issue to cause FreeRDP to crash,
resulting in a denial of service. (CVE-2024-32458)

Evgeny Legerov discovered that FreeRDP incorrectly handled certain memory
operations. A remote attacker could possibly use this issue to cause
FreeRDP clients and servers to crash, resulting in a denial of service.
(CVE-2024-32459)

It was discovered that FreeRDP incorrectly handled certain memory
operations. If a user were tricked into connecting to a malicious server, a
remote attacker could possibly use this issue to cause FreeRDP to crash,
resulting in a denial of service. (CVE-2024-32659, CVE-2024-32660)");

  script_tag(name:"affected", value:"'freerdp2' package(s) on Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client2-2t64", ver:"2.11.5+dfsg1-1ubuntu0.1~esm2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-server2-2t64", ver:"2.11.5+dfsg1-1ubuntu0.1~esm2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp2-2t64", ver:"2.11.5+dfsg1-1ubuntu0.1~esm2", rls:"UBUNTU24.04 LTS"))) {
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
