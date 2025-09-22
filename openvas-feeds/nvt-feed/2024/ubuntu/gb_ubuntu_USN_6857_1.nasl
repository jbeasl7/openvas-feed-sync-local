# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6857.1");
  script_cve_id("CVE-2021-28651", "CVE-2022-41318", "CVE-2023-49285", "CVE-2023-49286", "CVE-2023-50269", "CVE-2024-25617");
  script_tag(name:"creation_date", value:"2024-06-28 04:07:55 +0000 (Fri, 28 Jun 2024)");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-28 18:04:31 +0000 (Tue, 28 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-6857-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6857-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6857-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3' package(s) announced via the USN-6857-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joshua Rogers discovered that Squid incorrectly handled requests with the
urn: scheme. A remote attacker could possibly use this issue to cause
Squid to consume resources, leading to a denial of service. This issue
only affected Ubuntu 16.04 LTS. (CVE-2021-28651)

It was discovered that Squid incorrectly handled SSPI and SMB
authentication. A remote attacker could use this issue to cause Squid to
crash, resulting in a denial of service, or possibly obtain sensitive
information. This issue only affected Ubuntu 16.04 LTS. (CVE-2022-41318)

Joshua Rogers discovered that Squid incorrectly handled HTTP message
processing. A remote attacker could possibly use this issue to cause
Squid to crash, resulting in a denial of service. (CVE-2023-49285)

Joshua Rogers discovered that Squid incorrectly handled Helper process
management. A remote attacker could possibly use this issue to cause
Squid to crash, resulting in a denial of service. (CVE-2023-49286)

Joshua Rogers discovered that Squid incorrectly handled HTTP request
parsing. A remote attacker could possibly use this issue to cause
Squid to crash, resulting in a denial of service.
(CVE-2023-50269, CVE-2024-25617)");

  script_tag(name:"affected", value:"'squid3' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.12-1ubuntu7.16+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.5.12-1ubuntu7.16+esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.27-1ubuntu1.14+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.5.27-1ubuntu1.14+esm2", rls:"UBUNTU18.04 LTS"))) {
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
