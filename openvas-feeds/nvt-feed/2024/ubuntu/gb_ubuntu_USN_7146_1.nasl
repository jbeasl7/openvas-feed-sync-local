# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7146.1");
  script_cve_id("CVE-2017-7537", "CVE-2020-25715", "CVE-2022-2414");
  script_tag(name:"creation_date", value:"2024-12-10 15:13:06 +0000 (Tue, 10 Dec 2024)");
  script_version("2024-12-12T09:30:20+0000");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-04 20:25:01 +0000 (Thu, 04 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-7146-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7146-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7146-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dogtag-pki' package(s) announced via the USN-7146-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christina Fu discovered that Dogtag PKI accidentally enabled a mock
authentication plugin by default. An attacker could potentially use
this flaw to bypass the regular authentication process and trick the
CA server into issuing certificates. This issue only affected Ubuntu
16.04 LTS. (CVE-2017-7537)

It was discovered that Dogtag PKI did not properly sanitize user
input. An attacker could possibly use this issue to perform cross site
scripting and obtain sensitive information. This issue only affected
Ubuntu 22.04 LTS. (CVE-2020-25715)

It was discovered that the XML parser did not properly handle entity
expansion. A remote attacker could potentially retrieve the content of
arbitrary files by sending specially crafted HTTP requests. This issue
only affected Ubuntu 16.04 LTS. (CVE-2022-2414)");

  script_tag(name:"affected", value:"'dogtag-pki' package(s) on Ubuntu 16.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dogtag-pki", ver:"10.2.6+git20160317-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pki-base", ver:"10.2.6+git20160317-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pki-ca", ver:"10.2.6+git20160317-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pki-server", ver:"10.2.6+git20160317-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dogtag-pki", ver:"11.0.0-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pki-base", ver:"11.0.0-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pki-base-java", ver:"11.0.0-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pki-ca", ver:"11.0.0-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pki-server", ver:"11.0.0-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
