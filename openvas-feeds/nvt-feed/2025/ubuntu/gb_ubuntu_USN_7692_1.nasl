# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7692.1");
  script_cve_id("CVE-2021-38562", "CVE-2022-25802", "CVE-2022-25803", "CVE-2023-41259", "CVE-2023-41260", "CVE-2023-45024", "CVE-2024-3262", "CVE-2025-2545", "CVE-2025-30087", "CVE-2025-31500", "CVE-2025-31501");
  script_tag(name:"creation_date", value:"2025-08-19 04:05:11 +0000 (Tue, 19 Aug 2025)");
  script_version("2025-08-19T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-08-19 05:39:49 +0000 (Tue, 19 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 19:29:46 +0000 (Mon, 13 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-7692-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7692-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7692-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'request-tracker5' package(s) announced via the USN-7692-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Request Tracker was susceptible to timing
attacks. An attacker could possibly use this issue to access sensitive
information. This issue only affected Ubuntu 22.04 LTS. (CVE-2021-38562)

It was discovered that Request Tracker was susceptible to cross-site
scripting attacks when malicious attachments were supplied. An attacker
could possibly use this issue to execute arbitrary code. This issue
only affected Ubuntu 22.04 LTS. (CVE-2022-25802)

It was discovered that Request Tracker would incorrectly redirect users
in certain instances. An attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 22.04 LTS.
(CVE-2022-25803)

Tom Wolters discovered that Request Tracker could leak information when
malicious email headers were supplied. An attacker could possibly
use this issue to access sensitive information. This issue only
affected Ubuntu 22.04 LTS. (CVE-2023-41259, CVE-2023-41260)

It was discovered that Request Tracker could leak information through
its transaction search. An attacker with access to the transaction
query builder of Request Tracker could possibly use this issue to
access sensitive information. This issue only affected Ubuntu 22.04
LTS. (CVE-2023-45024)

It was discovered that Request Tracker erroneously stored ticket
information in a web browser's cache. An attacker with direct access to
a system could possibly use this issue to access sensitive information.
This issue only affected Ubuntu 22.04 LTS and Ubuntu 24.04 LTS.
(CVE-2024-3262)

It was discovered that Request Tracker made use of an obsolete
cryptographic algorithm for emails sent with S/MIME encryption. An
attacker could possibly use this issue to access sensitive information.
(CVE-2025-2545)

It was discovered that Request Tracker was susceptible to cross-site
scripting attacks when malicious parameters were included in a search
URL. An attacker could possibly use this issue to execute arbitrary
code. (CVE-2025-30087)

It was discovered that Request Tracker was susceptible to cross-site
scripting attacks when malicious permalinks or assets were provided.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2025-31500, CVE-2025-31501)");

  script_tag(name:"affected", value:"'request-tracker5' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker5", ver:"5.0.1+dfsg-1ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-fcgi", ver:"5.0.1+dfsg-1ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-standalone", ver:"5.0.1+dfsg-1ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker5", ver:"5.0.5+dfsg-2ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-fcgi", ver:"5.0.5+dfsg-2ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-standalone", ver:"5.0.5+dfsg-2ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker5", ver:"5.0.7+dfsg-2ubuntu0.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-fcgi", ver:"5.0.7+dfsg-2ubuntu0.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt5-standalone", ver:"5.0.7+dfsg-2ubuntu0.1", rls:"UBUNTU25.04"))) {
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
