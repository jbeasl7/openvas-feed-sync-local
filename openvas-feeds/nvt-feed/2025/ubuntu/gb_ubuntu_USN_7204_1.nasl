# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7204.1");
  script_cve_id("CVE-2018-14349", "CVE-2018-14350", "CVE-2018-14351", "CVE-2018-14352", "CVE-2018-14353", "CVE-2018-14354", "CVE-2018-14355", "CVE-2018-14356", "CVE-2018-14357", "CVE-2018-14358", "CVE-2018-14359", "CVE-2018-14360", "CVE-2018-14361", "CVE-2018-14362", "CVE-2018-14363", "CVE-2020-14954", "CVE-2020-28896", "CVE-2021-32055", "CVE-2022-1328", "CVE-2024-49393", "CVE-2024-49394");
  script_tag(name:"creation_date", value:"2025-01-16 10:56:48 +0000 (Thu, 16 Jan 2025)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-12 16:19:40 +0000 (Wed, 12 Sep 2018)");

  script_name("Ubuntu: Security Advisory (USN-7204-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7204-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7204-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'neomutt' package(s) announced via the USN-7204-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeriko One discovered that NeoMutt incorrectly handled certain IMAP
and POP3 responses. An attacker could possibly use this issue to
cause NeoMutt to crash, resulting in a denial of service, or
the execution of arbitrary code. This issue only affected
Ubuntu 18.04 LTS. (CVE-2018-14349, CVE-2018-14350, CVE-2018-14351,
CVE-2018-14352, CVE-2018-14353, CVE-2018-14354, CVE-2018-14355,
CVE-2018-14356, CVE-2018-14357, CVE-2018-14358, CVE-2018-14359,
CVE-2018-14362)

Jeriko One discovered that NeoMutt incorrectly handled certain
NNTP-related operations. An attacker could possibly use this issue
to cause NeoMutt to crash, resulting in denial of service, or
the execution of arbitrary code. This issue only affected
Ubuntu 18.04 LTS. (CVE-2018-14360, CVE-2018-14361, CVE-2018-14363)

It was discovered that NeoMutt incorrectly processed additional data
when communicating with mail servers. An attacker could possibly use
this issue to access senstive information. This issue only affected
Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-14954, CVE-2020-28896)

It was discovered that Neomutt incorrectly handled the IMAP QRSync
setting. An attacker could possibly use this issue to cause NeoMutt
to crash, resulting in denial of service. This issue only affected
Ubuntu 20.04 LTS. (CVE-2021-32055)

Tavis Ormandy discovered that NeoMutt incorrectly parsed uuencoded
text past the length of the string. An attacker could possibly use
this issue to enable the execution of arbitrary code. This issue
only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and
Ubuntu 22.04 LTS. (CVE-2022-1328)

It was discovered that NeoMutt did not properly encrypt email headers.
An attacker could possibly use this issue to receive emails that were
not intended for them and access sensitive information. This
vulnerability was only fixed in Ubuntu 20.04 LTS, Ubuntu 22.04 LTS,
and Ubuntu 24.04 LTS. (CVE-2024-49393, CVE-2024-49394)");

  script_tag(name:"affected", value:"'neomutt' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"neomutt", ver:"20171215+dfsg.1-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"neomutt", ver:"20191207+dfsg.1-1.1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"neomutt", ver:"20211029+dfsg1-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"neomutt", ver:"20231103+dfsg1-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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
