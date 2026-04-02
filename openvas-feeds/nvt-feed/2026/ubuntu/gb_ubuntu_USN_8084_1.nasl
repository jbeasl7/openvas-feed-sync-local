# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8084.1");
  script_cve_id("CVE-2025-0167", "CVE-2026-1965", "CVE-2026-3783", "CVE-2026-3784", "CVE-2026-3805");
  script_tag(name:"creation_date", value:"2026-03-16 04:53:37 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8084-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8084-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8084-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the USN-8084-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zhicheng Chen discovered that curl could incorrectly reuse the wrong
connection for Negotiate-authenticated HTTP or HTTPS requests. This could
result in the use of credentials from a different connection, contrary to
expectations. (CVE-2026-1965)

It was discovered that curl incorrectly leaked OAuth2 bearer tokens when
following a redirect. This could result in tokens being sent to the wrong
host, contrary to expectations. (CVE-2026-3783)

Muhamad Arga Reksapati discovered that curl incorrectly reused existing
HTTP proxy connections even if the request used different credentials. This
could result in the use of incorrect credentials, contrary to expectations.
(CVE-2026-3784)

Daniel Wade discovered that curl incorrectly handled certain memory
operations when doing a second SMB request to the same host. An attacker
could use this issue to cause curl to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 25.10. (CVE-2026-3805)

Yihang Zhou discovered that curl incorrectly reused .netrc file credentials
when following redirects. This could result in the use of credentials for
a different host, contrary to expectations. This issue only affected Ubuntu
22.04 LTS and Ubuntu 24.04 LTS. (CVE-2025-0167)");

  script_tag(name:"affected", value:"'curl' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.81.0-1ubuntu1.23", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.81.0-1ubuntu1.23", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.81.0-1ubuntu1.23", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4", ver:"7.81.0-1ubuntu1.23", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"8.5.0-2ubuntu10.8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3t64-gnutls", ver:"8.5.0-2ubuntu10.8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4t64", ver:"8.5.0-2ubuntu10.8", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"8.14.1-2ubuntu1.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3t64-gnutls", ver:"8.14.1-2ubuntu1.2", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl4t64", ver:"8.14.1-2ubuntu1.2", rls:"UBUNTU25.10"))) {
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
