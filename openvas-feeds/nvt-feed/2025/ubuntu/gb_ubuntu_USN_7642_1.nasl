# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7642.1");
  script_cve_id("CVE-2023-47627", "CVE-2023-49081", "CVE-2023-49082", "CVE-2024-23829", "CVE-2024-27306", "CVE-2024-30251", "CVE-2024-52304");
  script_tag(name:"creation_date", value:"2025-07-21 04:19:06 +0000 (Mon, 21 Jul 2025)");
  script_version("2025-08-18T05:42:33+0000");
  script_tag(name:"last_modification", value:"2025-08-18 05:42:33 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-15 17:36:18 +0000 (Fri, 15 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-7642-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7642-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7642-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-aiohttp' package(s) announced via the USN-7642-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ben Kallus discovered that AIOHTTP did not correctly parse HTTP
headers. A remote attacker could possibly use this issue to perform
request smuggling. This issue only affected Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2023-47627)

Ivan Novikov discovered that AIOHTTP did not properly validate certain
inputs. A remote attacker could possibly use this issue to perform request
smuggling. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2023-49081, CVE-2023-49082)

Paul J. Dorn discovered that AIOHTTP did not properly validate certain
inputs. A remote attacker could possibly use this issue to perform request
smuggling. This issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS and
Ubuntu 24.04 LTS. (CVE-2024-23829)

Takeshi Kaneko discovered that AIOHTTP did not properly sanitize certain
inputs. A remote attacker could possibly use this issue to perform a
cross-site scripting (XSS) attack. (CVE-2024-27306)

It was discovered that AIOHTTP did not correctly handle certain POST
requests. A remote attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 20.04 LTS,
Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2024-30251)

Jeppe Bonde Weikop discovered that AIOHTTP did not correctly handle
parsing newlines in certain inputs. A remote attacker could possibly use
this issue to perform request smuggling. (CVE-2024-52304)");

  script_tag(name:"affected", value:"'python-aiohttp' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-aiohttp", ver:"3.0.1-1ubuntu0.1~esm5", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-aiohttp", ver:"3.6.2-1ubuntu1+esm4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-aiohttp", ver:"3.8.1-4ubuntu0.2+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python3-aiohttp", ver:"3.9.1-1ubuntu0.1+esm1", rls:"UBUNTU24.04 LTS"))) {
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
