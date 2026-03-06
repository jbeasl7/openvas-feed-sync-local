# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8062.2");
  script_cve_id("CVE-2025-14017", "CVE-2025-15079", "CVE-2025-15224");
  script_tag(name:"creation_date", value:"2026-03-04 04:33:43 +0000 (Wed, 04 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8062-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8062-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8062-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the USN-8062-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-8062-1 fixed vulnerabilities in curl. This update provides the
corresponding update for CVE-2025-14017, CVE-2025-15079, and CVE-2025-15224
for Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04
LTS.

Original advisory details:

 It was discovered that curl incorrectly handled cookies when redirected
 from secure to insecure connections. An attacker could possibly use this
 issue to cause a denial of service, or obtain sensitive information.
 This issue only affected Ubuntu 25.10. (CVE-2025-9086)

 Calvin Ruocco discovered that curl did not properly handle WebSocket
 communications under certain circumstances. A malicious server could
 possibly use this issue to poison proxy caches with malicious content.
 This issue only affected Ubuntu 24.04 LTS and Ubuntu 25.10.
 (CVE-2025-10148)

 Stanislav Fort discovered that wcurl did not properly handle URLs with
 certain encoded characters. If a user were tricked into processing
 a specially crafted URL, an attacker could possibly use this issue to
 write files outside the intended directory. This issue only affected
 Ubuntu 25.10. (CVE-2025-11563)

 Stanislav Fort discovered that curl did not properly validate pinned
 public keys under certain circumstances. A remote attacker could
 possibly use this issue to perform a machine-in-the-middle attack. This
 issue only affected Ubuntu 25.10.(CVE-2025-13034)

 Stanislav Fort discovered that curl did not properly manage TLS options
 when performing LDAP over TLS transfers in multi-threaded environments.
 Under certain circumstances, certificate verification could be
 unintentionally and unknowingly disabled. (CVE-2025-14017)

 It was discovered that curl incorrectly handled Oauth2 bearer tokens
 when following redirects. A remote attacker could possibly use this
 issue to obtain authentication credentials. (CVE-2025-14524)

 Stanislav Fort discovered that curl did not properly validate TLS
 certificates when reusing connections. A remote attacker could possibly
 use this issue to bypass expected certificate verification. This issue
 only affected Ubuntu 24.04 LTS and Ubuntu 25.10. (CVE-2025-14819)

 Harry Sintonen discovered that curl did not properly validate SSH host
 keys when performing SSH-based file transfers. This issue could lead to
 unintended bypass of custom known_hosts file. This issue only
 affected Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2025-15079)

 Harry Sintonen discovered that curl built with libssh did not properly
 handle authentication when performing SSH-based file transfers. This
 could result in unintended authentication operations. This issue only
 affected Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. (CVE-2025-15224)");

  script_tag(name:"affected", value:"'curl' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.35.0-1ubuntu2.20+esm19", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.35.0-1ubuntu2.20+esm19", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.47.0-1ubuntu2.19+esm15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.47.0-1ubuntu2.19+esm15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.58.0-2ubuntu3.24+esm7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4", ver:"7.58.0-2ubuntu3.24+esm7", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.68.0-1ubuntu2.25+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4", ver:"7.68.0-1ubuntu2.25+esm2", rls:"UBUNTU20.04 LTS"))) {
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
