# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8136.1");
  script_cve_id("CVE-2025-59028", "CVE-2025-59031", "CVE-2025-59032", "CVE-2026-0394", "CVE-2026-24031", "CVE-2026-27855", "CVE-2026-27856", "CVE-2026-27857", "CVE-2026-27858", "CVE-2026-27859", "CVE-2026-27860");
  script_tag(name:"creation_date", value:"2026-04-01 04:57:46 +0000 (Wed, 01 Apr 2026)");
  script_version("2026-04-01T06:13:16+0000");
  script_tag(name:"last_modification", value:"2026-04-01 06:13:16 +0000 (Wed, 01 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8136-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8136-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8136-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot' package(s) announced via the USN-8136-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Dovecot incorrectly handled invalid base64 SASL data.
An attacker could possibly use this issue to cause a denial of service. This
issue only affected Ubuntu 25.10. (CVE-2025-59028)

It was discovered that Dovecot script decode2text.sh incorrectly handled zip
files. An attacker could possibly use this issue to obtain sensitive
information. (CVE-2025-59031)

It was discovered that Dovecot incorrectly handled certain AUTHENTICATE
requests. An attacker could possibly use this issue to cause a denial of
service. (CVE-2025-59032)

It was discovered that Dovecot incorrectly handled certain SQL based
authentication. An attacker could possibly use this issue to bypass
authentication. This issue only affected Ubuntu 25.10. (CVE-2026-24031)

It was discovered that Dovecot incorrectly handled certain LDAP based
authentication. An attacker could possibly use this issue to bypass
restrictions and allow probing of LDAP structure. This issue only affected
Ubuntu 25.10. (CVE-2026-27860)

It was discovered that Dovecot is vulnerable to replay attack under
certain conditions. An attacker could possibly use this issue to bypass
authentication. (CVE-2026-27855)

It was discovered that Dovecot is vulnerable to a timing attack under
certain conditions. An attacker could possibly use this issue to bypass
authentication. (CVE-2026-27856)

It was discovered that Dovecot incorrectly handled certain IMAP login
requests. An attacker could possibly use this issue to cause a denial of
service. (CVE-2026-27857)

It was discovered that Dovecot incorrectly handled certain specially
crafted messages. An attacker could possibly use this issue to cause a
denial of service. (CVE-2026-27858)

It was discovered that Dovecot incorrectly handled certain specially
crafted mail messages. An attacker could possibly use this issue to
cause a denial of service. (CVE-2026-27859)

It was discovered that Dovecot incorrectly handles file paths. A attacker
could possibly use this issue to perform a path traversal and obtain or
modify arbitrary files. This issue only affected Ubuntu 22.04 LTS and
Ubuntu 24.04 LTS. (CVE-2026-0394)");

  script_tag(name:"affected", value:"'dovecot' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.3.16+dfsg1-3ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.3.21+dfsg1-2ubuntu6.3", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.4.1+dfsg1-5ubuntu4.1", rls:"UBUNTU25.10"))) {
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
