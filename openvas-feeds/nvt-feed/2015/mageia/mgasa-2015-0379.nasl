# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130012");
  script_cve_id("CVE-2015-5567", "CVE-2015-5568", "CVE-2015-5570", "CVE-2015-5571", "CVE-2015-5572", "CVE-2015-5573", "CVE-2015-5574", "CVE-2015-5575", "CVE-2015-5576", "CVE-2015-5577", "CVE-2015-5578", "CVE-2015-5579", "CVE-2015-5580", "CVE-2015-5581", "CVE-2015-5582", "CVE-2015-5584", "CVE-2015-5587", "CVE-2015-5588", "CVE-2015-6676", "CVE-2015-6677", "CVE-2015-6678", "CVE-2015-6679", "CVE-2015-6682");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:30 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0379)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0379");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0379.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16792");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-23.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2015-0379 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.521 contains fixes to critical security
vulnerabilities found in earlier versions that could potentially allow an
attacker to take control of the affected system.

This update resolves a type confusion vulnerability that could lead to code
execution (CVE-2015-5573).

This update resolves use-after-free vulnerabilities that could lead to code
execution (CVE-2015-5570, CVE-2015-5574, CVE-2015-5581, CVE-2015-5584,
CVE-2015-6682).

This update resolves buffer overflow vulnerabilities that could lead to
code execution (CVE-2015-6676, CVE-2015-6678).

This update resolves memory corruption vulnerabilities that could lead to
code execution (CVE-2015-5575, CVE-2015-5577, CVE-2015-5578, CVE-2015-5580,
CVE-2015-5582, CVE-2015-5588, CVE-2015-6677).

This update includes additional validation checks to ensure that Flash
Player rejects malicious content from vulnerable JSONP callback APIs
(CVE-2015-5571).

This update resolves a memory leak vulnerability (CVE-2015-5576).

This update includes further hardening to a mitigation to defend against
vector length corruptions (CVE-2015-5568).

This update resolves stack corruption vulnerabilities that could lead to
code execution (CVE-2015-5567, CVE-2015-5579).

This update resolves a stack overflow vulnerability that could lead to code
execution (CVE-2015-5587).

This update resolves a security bypass vulnerability that could lead to
information disclosure (CVE-2015-5572).

This update resolves a vulnerability that could be exploited to bypass the
same-origin-policy and lead to information disclosure (CVE-2015-6679).");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.521~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.521~1.mga5.nonfree", rls:"MAGEIA5"))) {
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
