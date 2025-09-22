# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7688.1");
  script_cve_id("CVE-2020-14342", "CVE-2021-20208", "CVE-2022-27239", "CVE-2022-29869");
  script_tag(name:"creation_date", value:"2025-08-13 04:10:29 +0000 (Wed, 13 Aug 2025)");
  script_version("2025-08-14T05:40:53+0000");
  script_tag(name:"last_modification", value:"2025-08-14 05:40:53 +0000 (Thu, 14 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-06 18:49:22 +0000 (Fri, 06 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-7688-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7688-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7688-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cifs-utils' package(s) announced via the USN-7688-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aurelien Aptel discovered that cifs-utils invoked a shell when requesting a
password. In certain environments, a local attacker could possibly use this
issue to escalate privileges. (CVE-2020-14342)

It was discovered that cifs-utils incorrectly used host credentials when
mounting a krb5 CIFS file system from within a container. An attacker
inside a container could possibly use this issue to obtain access to
sensitive information. (CVE-2021-20208)

It was discovered that cifs-utils incorrectly handled certain command-line
arguments. A local attacker could possibly use this issue to obtain root
privileges. (CVE-2022-27239)

It was discovered that cifs-utils incorrectly handled verbose logging. A
local attacker could possibly use this issue to obtain sensitive
information. (CVE-2022-29869)");

  script_tag(name:"affected", value:"'cifs-utils' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"cifs-utils", ver:"2:6.0-1ubuntu2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"cifs-utils", ver:"2:6.4-1ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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
