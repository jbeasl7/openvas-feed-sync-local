# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7647.1");
  script_cve_id("CVE-2021-3693", "CVE-2021-3694", "CVE-2021-3731", "CVE-2021-3882", "CVE-2024-23831");
  script_tag(name:"creation_date", value:"2025-07-21 04:19:06 +0000 (Mon, 21 Jul 2025)");
  script_version("2025-07-21T05:44:15+0000");
  script_tag(name:"last_modification", value:"2025-07-21 05:44:15 +0000 (Mon, 21 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-27 15:02:29 +0000 (Fri, 27 Aug 2021)");

  script_name("Ubuntu: Security Advisory (USN-7647-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7647-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7647-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ledgersmb' package(s) announced via the USN-7647-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that LedgerSMB did not check the origin of HTML
fragments. An attacker could possibly use this issue to send a
maliciously crafted URL to the server and obtain sensitive
information, or execute arbitrary code. This issue only affected
Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu 25.04.
(CVE-2021-3693)

It was discovered that LedgerSMB did not properly encode HTML
error messages. An attacker could possibly use this issue to send
a maliciously crafted URL to the server and obtain sensitive
information, or execute arbitrary code. This issue only affected
Ubuntu 18.04 LTS. (CVE-2021-3694)

It was discovered that LedgerSMB did not guard against discrete
link redirections. An attacker could possibly use this issue to
obtain sensitive information. This issue only affected Ubuntu
16.04 LTS and Ubuntu 18.04 LTS. (CVE-2021-3731)

It was discovered that LedgerSMB did not properly set the 'Secure'
attribute during HTTPS sessions. If a user were tricked into using
an unencrypted connection, an attacker could possibly use this
issue to obtain sensitive information. This issue only affected
Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu
25.04. (CVE-2021-3882)

It was discovered that LedgerSMB could create admin accounts via
a URL. If an admin were tricked into clicking a maliciously
crafted URL, an attacker could possibly use this issue to
achieve privilege escalation. This issue only affected Ubuntu 20.04
LTS, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu 25.04.
(CVE-2024-23831)");

  script_tag(name:"affected", value:"'ledgersmb' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ledgersmb", ver:"1.3.46-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ledgersmb", ver:"1.4.42+ds-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ledgersmb", ver:"1.6.9+ds-1ubuntu0.1+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ledgersmb", ver:"1.6.33+ds-1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ledgersmb", ver:"1.6.33+ds-2.1ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"ledgersmb", ver:"1.6.33+ds-2.2ubuntu0.25.04.1", rls:"UBUNTU25.04"))) {
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
