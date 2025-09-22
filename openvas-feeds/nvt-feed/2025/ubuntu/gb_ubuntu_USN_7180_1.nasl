# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7180.1");
  script_cve_id("CVE-2022-48560", "CVE-2022-48565", "CVE-2022-48566", "CVE-2023-24329", "CVE-2023-40217");
  script_tag(name:"creation_date", value:"2025-01-07 04:09:04 +0000 (Tue, 07 Jan 2025)");
  script_version("2025-01-07T06:11:07+0000");
  script_tag(name:"last_modification", value:"2025-01-07 06:11:07 +0000 (Tue, 07 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-01 13:36:41 +0000 (Fri, 01 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-7180-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7180-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7180-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7' package(s) announced via the USN-7180-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python incorrectly handled certain scripts.
An attacker could possibly use this issue to execute arbitrary code
or cause a crash. (CVE-2022-48560)

It was discovered that Python did not properly handle XML entity
declarations in plist files. An attacker could possibly use this
vulnerability to perform an XML External Entity (XXE) injection,
resulting in a denial of service or information disclosure.
(CVE-2022-48565)

It was discovered that Python did not properly provide constant-time
processing for a crypto operation. An attacker could possibly use this
issue to perform a timing attack and recover sensitive information.
(CVE-2022-48566)

It was discovered that Python incorrectly handled certain inputs. If a
user or an automated system were tricked into running a specially
crafted input, a remote attacker could possibly use this issue to cause a
denial of service. (CVE-2023-24329)

It was discovered that Python instances of ssl.SSLSocket were vulnerable
to a bypass of the TLS handshake. An attacker could possibly use this
issue to cause applications to treat unauthenticated received data before
TLS handshake as authenticated data after TLS handshake.
(CVE-2023-40217)");

  script_tag(name:"affected", value:"'python2.7' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.18-1~20.04.7", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.18-13ubuntu1.5", rls:"UBUNTU22.04 LTS"))) {
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
