# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7629.2");
  script_cve_id("CVE-2024-7254", "CVE-2025-4565");
  script_tag(name:"creation_date", value:"2025-09-04 04:07:10 +0000 (Thu, 04 Sep 2025)");
  script_version("2025-09-04T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-09-04 05:39:49 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-30 16:10:38 +0000 (Wed, 30 Jul 2025)");

  script_name("Ubuntu: Security Advisory (USN-7629-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7629-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7629-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'protobuf' package(s) announced via the USN-7629-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7435-1 and USN-7629-1 fixed vulnerabilities in Protocol Buffers
for several releases of Ubuntu. This update provides the corresponding
fixes for Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04 LTS.

Original advisory details:

 It was discovered that Protocol Buffers incorrectly handled memory when
 receiving malicious input using the Python bindings. An attacker could
 possibly use this issue to cause a denial of service. (CVE-2025-4565)

 It was discovered that Protocol Buffers incorrectly handled memory when
 receiving malicious input using the Java bindings. An attacker could
 possibly use this issue to cause a denial of service. This issue only
 affected Ubuntu 25.04. (CVE-2024-7254)");

  script_tag(name:"affected", value:"'protobuf' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libprotobuf-java", ver:"2.6.1-1.3ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-protobuf", ver:"2.6.1-1.3ubuntu0.1~esm4", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libprotobuf-java", ver:"3.0.0-9.1ubuntu1.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-protobuf", ver:"3.0.0-9.1ubuntu1.1+esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libprotobuf-java", ver:"3.6.1.3-2ubuntu5.2+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-protobuf", ver:"3.6.1.3-2ubuntu5.2+esm2", rls:"UBUNTU20.04 LTS"))) {
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
