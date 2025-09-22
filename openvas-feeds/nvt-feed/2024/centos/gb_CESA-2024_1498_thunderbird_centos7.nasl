# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884338");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-5388", "CVE-2024-0743", "CVE-2024-1936", "CVE-2024-2607", "CVE-2024-2608", "CVE-2024-2610", "CVE-2024-2611", "CVE-2024-2612", "CVE-2024-2614");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 14:47:29 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-04-04 01:06:48 +0000 (Thu, 04 Apr 2024)");
  script_name("CentOS: Security Advisory for thunderbird (CESA-2024:1498)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2024:1498");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2024-April/099238.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2024:1498 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This Update upgrades Thunderbird to version 115.9.0.

Security Fix(es):

  * nss: timing attack against RSA decryption (CVE-2023-5388)

  * Mozilla: Crash in NSS TLS method (CVE-2024-0743)

  * Mozilla: Leaking of encrypted email subjects to other conversations  (CVE-2024-1936)

  * Mozilla: JIT code failed to save return registers on Armv7-A (CVE-2024-2607)

  * Mozilla: Integer overflow could have led to out of bounds write
(CVE-2024-2608)

  * Mozilla: Improper handling of html and body tags enabled CSP nonce leakage
(CVE-2024-2610)

  * Mozilla: Clickjacking vulnerability could have led to a user accidentally
granting permissions (CVE-2024-2611)

  * Mozilla: Self referencing object could have potentially led to a
use-after-free (CVE-2024-2612)

  * Mozilla: Memory safety bugs fixed in Firefox 124, Firefox ESR 115.9, and
Thunderbird 115.9 (CVE-2024-2614)
For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.");

  script_tag(name:"affected", value:"'thunderbird' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~115.9.0~1.el7.centos", rls:"CentOS7"))) {
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