# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7338.1");
  script_cve_id("CVE-2024-21208", "CVE-2024-21210", "CVE-2024-21217", "CVE-2024-21235", "CVE-2025-21502");
  script_tag(name:"creation_date", value:"2025-03-12 04:04:15 +0000 (Wed, 12 Mar 2025)");
  script_version("2025-03-12T05:38:19+0000");
  script_tag(name:"last_modification", value:"2025-03-12 05:38:19 +0000 (Wed, 12 Mar 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 21:15:15 +0000 (Tue, 21 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-7338-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.10");

  script_xref(name:"Advisory-ID", value:"USN-7338-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7338-1");
  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2024-10-15");
  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2025-01-21");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-17-crac' package(s) announced via the USN-7338-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Boothe discovered that the Networking component of CRaC JDK 17 did not
properly handle access under certain circumstances. An unauthenticated
attacker could possibly use this issue to cause a denial of service.
(CVE-2024-21208)

It was discovered that the Hotspot component of CRaC JDK 17 did not
properly handle vectorization under certain circumstances. An
unauthenticated attacker could possibly use this issue to access
unauthorized resources and expose sensitive information.
(CVE-2024-21210, CVE-2024-21235)

It was discovered that the Serialization component of CRaC JDK 17 did not
properly handle deserialization under certain circumstances. An
unauthenticated attacker could possibly use this issue to cause a denial
of service. (CVE-2024-21217)

It was discovered that the Hotspot component of CRaC JDK 17 did not
properly handle API access under certain circumstances. An unauthenticated
attacker could possibly use this issue to access unauthorized resources
and expose sensitive information. (CVE-2025-21502)

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:
[links moved to references]");

  script_tag(name:"affected", value:"'openjdk-17-crac' package(s) on Ubuntu 24.10.");

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

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jdk", ver:"17.0.14+7-0ubuntu1~24.10", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jdk-headless", ver:"17.0.14+7-0ubuntu1~24.10", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jre", ver:"17.0.14+7-0ubuntu1~24.10", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jre-headless", ver:"17.0.14+7-0ubuntu1~24.10", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-crac-jre-zero", ver:"17.0.14+7-0ubuntu1~24.10", rls:"UBUNTU24.10"))) {
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
