# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8117.1");
  script_cve_id("CVE-2026-25075");
  script_tag(name:"creation_date", value:"2026-03-24 04:37:32 +0000 (Tue, 24 Mar 2026)");
  script_version("2026-03-24T05:57:14+0000");
  script_tag(name:"last_modification", value:"2026-03-24 05:57:14 +0000 (Tue, 24 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-23 19:16:39 +0000 (Mon, 23 Mar 2026)");

  script_name("Ubuntu: Security Advisory (USN-8117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8117-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8117-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan' package(s) announced via the USN-8117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kazuma Matsumoto discovered that strongSwan incorrectly handled EAP-TTLS
AVPs when using the eap-ttls plugin. An attacker could possibly use this
issue to cause strongSwan to consume resources and crash, resulting in a
denial of service.");

  script_tag(name:"affected", value:"'strongswan' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.9.5-2ubuntu2.5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.9.5-2ubuntu2.5", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.9.13-2ubuntu4.24.04.2", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.9.13-2ubuntu4.24.04.2", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"6.0.1-6ubuntu4.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"6.0.1-6ubuntu4.2", rls:"UBUNTU25.10"))) {
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
