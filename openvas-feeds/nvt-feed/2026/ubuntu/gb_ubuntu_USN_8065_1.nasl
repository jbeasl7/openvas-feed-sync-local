# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8065.1");
  script_cve_id("CVE-2024-37568", "CVE-2025-59420", "CVE-2025-61920", "CVE-2025-62706", "CVE-2025-68158");
  script_tag(name:"creation_date", value:"2026-03-02 04:35:29 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-22 17:04:38 +0000 (Thu, 22 Jan 2026)");

  script_name("Ubuntu: Security Advisory (USN-8065-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8065-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8065-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-authlib' package(s) announced via the USN-8065-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Millie Solem discovered that Authlib did not properly restrict algorithm
selection during JWT verification, allowing HMAC verification with
asymmetric public keys when no algorithm was specified. A remote attacker
could possibly use this issue to bypass signature verification and forge
tokens, resulting in authentication bypass or privilege escalation.
(CVE-2024-37568)

Muhammad Noman Ilyas discovered that Authlib did not properly enforce
critical header parameter handling during JSON Web Signature verification,
leading to unknown critical parameters being incorrectly accepted. A remote
attacker could possibly use this issue to bypass security policies in mixed
deployments, resulting in authentication bypass, replay attacks, or
privilege escalation. (CVE-2025-59420)

Muhammad Noman Ilyas discovered that Authlib did not properly limit the
size of JSON Web Signature or JSON Web Token header and signature segments.
A remote attacker could possibly use this issue to cause excessive memory
or processor consumption, leading to a denial of service. (CVE-2025-61920)

Muhammad Noman Ilyas discovered that Authlib performed unbounded
decompression when processing certain compressed encrypted tokens. A remote
attacker could possibly use this issue to send a specially crafted token
that can be expanded to a large size during decompression, causing a denial
of service. (CVE-2025-62706)

It was discovered that Authlib did not properly bind cached state
information to the initiating user session during OAuth authentication
flows. A remote attacker could possibly use this issue to perform cross-
site request forgery attacks, resulting in unauthorized actions or
authentication bypass. This issue only affected Ubuntu 24.04 LTS.
(CVE-2025-68158)");

  script_tag(name:"affected", value:"'python-authlib' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-authlib-doc", ver:"0.15.5-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-authlib", ver:"0.15.5-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-authlib-doc", ver:"1.3.0-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-authlib", ver:"1.3.0-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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
