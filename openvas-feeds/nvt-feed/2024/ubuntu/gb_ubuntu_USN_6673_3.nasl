# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6673.3");
  script_cve_id("CVE-2024-26130");
  script_tag(name:"creation_date", value:"2024-05-28 04:09:19 +0000 (Tue, 28 May 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-05 22:09:20 +0000 (Wed, 05 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-6673-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6673-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6673-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-cryptography' package(s) announced via the USN-6673-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6673-1 provided a security update for python-cryptography.
This update provides the corresponding update for Ubuntu 24.04 LTS.

Original advisory details:

 It was discovered that python-cryptography incorrectly handled memory
 operations when processing mismatched PKCS#12 keys. A remote attacker could
 possibly use this issue to cause python-cryptography to crash, leading to a
 denial of service. This issue only affected Ubuntu 23.10. (CVE-2024-26130)");

  script_tag(name:"affected", value:"'python-cryptography' package(s) on Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-cryptography", ver:"41.0.7-4ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
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
