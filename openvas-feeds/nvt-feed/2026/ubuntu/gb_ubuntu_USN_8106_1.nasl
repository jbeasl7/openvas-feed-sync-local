# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8106.1");
  script_cve_id("CVE-2025-67733", "CVE-2026-21863");
  script_tag(name:"creation_date", value:"2026-03-19 04:39:53 +0000 (Thu, 19 Mar 2026)");
  script_version("2026-03-19T05:56:32+0000");
  script_tag(name:"last_modification", value:"2026-03-19 05:56:32 +0000 (Thu, 19 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-25 17:34:02 +0000 (Wed, 25 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-8106-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8106-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8106-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'valkey' package(s) announced via the USN-8106-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Valkey incorrectly handled errors for lua scripts.
An attacker could possibly use this issue to inject arbitrary information
into the response stream for other clients. (CVE-2025-67733)

It was discovered that Valkey incorrectly handled malformed cluster bus
messages. A remote attacker could possibly use this issue to cause Valkey
to crash, resulting in a denial of service. (CVE-2026-21863)");

  script_tag(name:"affected", value:"'valkey' package(s) on Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"valkey-server", ver:"7.2.12+dfsg1-0ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"valkey-server", ver:"8.1.6+dfsg1-0ubuntu0.1", rls:"UBUNTU25.10"))) {
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
