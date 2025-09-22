# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842552");
  script_cve_id("CVE-2015-1794", "CVE-2015-3193", "CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196");
  script_tag(name:"creation_date", value:"2015-12-08 09:53:48 +0000 (Tue, 08 Dec 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-07 17:46:25 +0000 (Mon, 07 Dec 2015)");

  script_name("Ubuntu: Security Advisory (USN-2830-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.04|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2830-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2830-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-2830-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Guy Leaver discovered that OpenSSL incorrectly handled a ServerKeyExchange
for an anonymous DH ciphersuite with the value of p set to 0. A remote
attacker could possibly use this issue to cause OpenSSL to crash, resulting
in a denial of service. This issue only applied to Ubuntu 15.10.
(CVE-2015-1794)

Hanno Bock discovered that the OpenSSL Montgomery squaring procedure
algorithm may produce incorrect results when being used on x86_64. A remote
attacker could possibly use this issue to break encryption. This issue only
applied to Ubuntu 15.10. (CVE-2015-3193)

Loic Jonas Etienne discovered that OpenSSL incorrectly handled ASN.1
signatures with a missing PSS parameter. A remote attacker could possibly
use this issue to cause OpenSSL to crash, resulting in a denial of service.
(CVE-2015-3194)

Adam Langley discovered that OpenSSL incorrectly handled malformed
X509_ATTRIBUTE structures. A remote attacker could possibly use this issue
to cause OpenSSL to consume resources, resulting in a denial of service.
(CVE-2015-3195)

It was discovered that OpenSSL incorrectly handled PSK identity hints. A
remote attacker could possibly use this issue to cause OpenSSL to crash,
resulting in a denial of service. This issue only applied to Ubuntu 12.04
LTS, Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-3196)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.32", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu2.16", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu11.5", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2d-0ubuntu1.2", rls:"UBUNTU15.10"))) {
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
