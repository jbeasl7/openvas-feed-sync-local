# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844998");
  script_cve_id("CVE-2020-29129", "CVE-2020-29130", "CVE-2021-3592", "CVE-2021-3593", "CVE-2021-3594", "CVE-2021-3595");
  script_tag(name:"creation_date", value:"2021-07-16 03:00:52 +0000 (Fri, 16 Jul 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-30 16:33:29 +0000 (Mon, 30 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-5009-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|20\.10|21\.04)");

  script_xref(name:"Advisory-ID", value:"USN-5009-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5009-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libslirp' package(s) announced via the USN-5009-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qiuhao Li discovered that libslirp incorrectly handled certain header data
lengths. An attacker inside a guest could possibly use this issue to leak
sensitive information from the host. This issue only affected Ubuntu 20.04
LTS and Ubuntu 20.10. (CVE-2020-29129, CVE-2020-29130)

It was discovered that libslirp incorrectly handled certain udp packets. An
attacker inside a guest could possibly use this issue to leak sensitive
information from the host. (CVE-2021-3592, CVE-2021-3593, CVE-2021-3594,
CVE-2021-3595)");

  script_tag(name:"affected", value:"'libslirp' package(s) on Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libslirp0", ver:"4.1.0-2ubuntu2.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libslirp0", ver:"4.3.1-1ubuntu0.1", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libslirp0", ver:"4.4.0-1ubuntu0.1", rls:"UBUNTU21.04"))) {
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
