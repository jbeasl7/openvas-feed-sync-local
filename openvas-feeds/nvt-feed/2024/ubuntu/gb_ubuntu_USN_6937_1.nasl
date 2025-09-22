# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6937.1");
  script_cve_id("CVE-2024-2511", "CVE-2024-4603", "CVE-2024-4741", "CVE-2024-5535");
  script_tag(name:"creation_date", value:"2024-08-01 04:08:31 +0000 (Thu, 01 Aug 2024)");
  script_version("2024-08-01T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-01 05:05:42 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6937-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6937-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6937-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-6937-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSSL incorrectly handled TLSv1.3 sessions when
certain non-default TLS server configurations were in use. A remote
attacker could possibly use this issue to cause OpenSSL to consume
resources, leading to a denial of service. (CVE-2024-2511)

It was discovered that OpenSSL incorrectly handled checking excessively
long DSA keys or parameters. A remote attacker could possibly use this
issue to cause OpenSSL to consume resources, leading to a denial of
service. This issue only affected Ubuntu 22.04 LTS and Ubuntu 24.04 LTS.
(CVE-2024-4603)

William Ahern discovered that OpenSSL incorrectly handled certain memory
operations in a rarely-used API. A remote attacker could use this issue to
cause OpenSSL to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2024-4741)

Joseph Birr-Pixton discovered that OpenSSL incorrectly handled calling a
certain API with an empty supported client protocols buffer. A remote
attacker could possibly use this issue to obtain sensitive information, or
cause OpenSSL to crash, resulting in a denial of service. (CVE-2024-5535)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1f-1ubuntu2.23", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.2-0ubuntu1.17", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl3t64", ver:"3.0.13-0ubuntu3.2", rls:"UBUNTU24.04 LTS"))) {
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
