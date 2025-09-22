# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0046");
  script_cve_id("CVE-2023-46809", "CVE-2024-21892", "CVE-2024-22019", "CVE-2024-22025");
  script_tag(name:"creation_date", value:"2024-02-23 04:11:56 +0000 (Fri, 23 Feb 2024)");
  script_version("2025-02-13T05:37:41+0000");
  script_tag(name:"last_modification", value:"2025-02-13 05:37:41 +0000 (Thu, 13 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-12 15:03:13 +0000 (Wed, 12 Feb 2025)");

  script_name("Mageia: Security Advisory (MGASA-2024-0046)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0046");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0046.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32861");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v18.19.0");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v18.19.1");
  script_xref(name:"URL", value:"https://github.com/yarnpkg/yarn/releases/tag/v1.22.20");
  script_xref(name:"URL", value:"https://github.com/yarnpkg/yarn/releases/tag/v1.22.21");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/february-2024-security-releases");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs, yarnpkg' package(s) announced via the MGASA-2024-0046 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a security release. The following CVEs are fixed in this
release:
CVE-2024-21892 - Code injection and privilege escalation through Linux
capabilities- (High)
CVE-2024-22019 - http: Reading unprocessed HTTP request with unbounded
chunk extension allows DoS attacks- (High)
CVE-2023-46809 - Node.js is vulnerable to the Marvin Attack (timing
variant of the Bleichenbacher attack against PKCS#1 v1.5 padding) -
(Medium)
CVE-2024-22025 - Denial of Service by resource exhaustion in fetch()
brotli decoding - (Medium)
More detailed information on each of the vulnerabilities can be found in
february 2024 Security Releases blog post.");

  script_tag(name:"affected", value:"'nodejs, yarnpkg' package(s) on Mageia 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~18.19.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~18.19.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~18.19.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~18.19.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~10.2.4~1.18.19.1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~10.2.154.26.mga9~5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yarnpkg", rpm:"yarnpkg~1.22.21~0.10.2.4.1.mga9", rls:"MAGEIA9"))) {
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
