# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7250.1");
  script_cve_id("CVE-2018-18836", "CVE-2018-18837", "CVE-2018-18838", "CVE-2023-22497", "CVE-2024-23722", "CVE-2024-34250", "CVE-2024-34251");
  script_tag(name:"creation_date", value:"2025-02-03 09:59:57 +0000 (Mon, 03 Feb 2025)");
  script_version("2025-02-04T05:37:53+0000");
  script_tag(name:"last_modification", value:"2025-02-04 05:37:53 +0000 (Tue, 04 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-24 17:35:46 +0000 (Tue, 24 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-7250-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7250-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7250-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netdata' package(s) announced via the USN-7250-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Netdata incorrectly handled parsing JSON input,
which could lead to a JSON injection. An attacker could possibly use
this issue to execute arbitrary code. This issue only affected
Ubuntu 18.04 LTS. (CVE-2018-18836)

It was discovered that Netdata incorrectly handled parsing HTTP headers,
which could lead to a HTTP header injection. An attacker could possibly
use this issue to cause a denial of service or leak sensitive information.
This issue only affected Ubuntu 18.04 LTS. (CVE-2018-18837)

It was discovered that Netdata incorrectly handled parsing URLs, which
could lead to a log injection. An attacker could possibly use this issue
to consume system resources, resulting in a denial of service. This issue
only affected Ubuntu 18.04 LTS. (CVE-2018-18838)

It was discovered Netdata improperly authenticated API keys. An attacker
could possibly use this issue to leak sensitive information or execute
arbitrary code. This issue only affected Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2023-22497)

It was discovered Fluent Bit, vendored in Netdata, incorrectly handled
parsing HTTP payloads. An attacker could possibly use this issue to
disrupt logging. This issue only affected Ubuntu 24.10. (CVE-2024-23722)

It was discovered that WebAssembly Micro Runtime, vendored in Netdata,
incorrectly handled memory. An attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 24.10.
(CVE-2024-34250, CVE-2024-34251)");

  script_tag(name:"affected", value:"'netdata' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"netdata", ver:"1.9.0+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"netdata-data", ver:"1.9.0+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"netdata-core", ver:"1.19.0-3ubuntu1+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"netdata-core", ver:"1.33.1-1ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"netdata-plugins-bash", ver:"1.33.1-1ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"netdata-web", ver:"1.33.1-1ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"netdata-core", ver:"1.44.3-2ubuntu0.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"netdata-plugins-bash", ver:"1.44.3-2ubuntu0.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"netdata-web", ver:"1.44.3-2ubuntu0.1", rls:"UBUNTU24.10"))) {
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
