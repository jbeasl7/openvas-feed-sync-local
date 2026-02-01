# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7966.1");
  script_cve_id("CVE-2022-29189", "CVE-2022-29190", "CVE-2022-29222");
  script_tag(name:"creation_date", value:"2026-01-20 08:35:13 +0000 (Tue, 20 Jan 2026)");
  script_version("2026-01-21T05:50:46+0000");
  script_tag(name:"last_modification", value:"2026-01-21 05:50:46 +0000 (Wed, 21 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 15:05:11 +0000 (Wed, 08 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-7966-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7966-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7966-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'snowflake' package(s) announced via the USN-7966-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Pion DTLS, vendored in Snowflake, did not impose a limit
on the amount of data that was buffered during the handshake. An attacker could
possibly use the issue to cause a denial of service. (CVE-2022-29189)

It was discovered that Pion DTLS, vendored in Snowflake, did not prevent the
fragmentBuffer from processing zero length fragments. An attacker could
possibly use the issue to cause a denial of service. (CVE-2022-29190)

It was discovered that Pion DTLS, vendored in Snowflake, did not require
CertificateVerify when Client Cert was sent. An attacker could
possibly use the issue to cause a denial of service. (CVE-2022-29222)");

  script_tag(name:"affected", value:"'snowflake' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"snowflake-client", ver:"1.1.0-2ubuntu0.1+esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snowflake-proxy", ver:"1.1.0-2ubuntu0.1+esm2", rls:"UBUNTU22.04 LTS"))) {
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
