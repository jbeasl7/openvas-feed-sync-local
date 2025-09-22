# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0041");
  script_cve_id("CVE-2023-50387", "CVE-2023-50868");
  script_tag(name:"creation_date", value:"2024-02-19 04:13:47 +0000 (Mon, 19 Feb 2024)");
  script_version("2024-02-21T05:06:26+0000");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:26 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:55:30 +0000 (Tue, 20 Feb 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0041)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0041");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0041.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32853");
  script_xref(name:"URL", value:"https://thekelleys.org.uk/dnsmasq/CHANGELOG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the MGASA-2024-0041 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This updated dnsmasq package fixes security issues:
Certain DNSSEC aspects of the DNS protocol allow a remote attacker to
trigger a denial of service via extreme consumption of resource caused
by DNSSEC query or response:
- KeyTrap - Extreme CPU consumption in DNSSEC validator.
 (CVE-2023-50387)
- Preparing an NSEC3 closest encloser proof can exhaust CPU resources.
 (CVE-2023-50868)

This update also fixes issues with udp packet size (fix already present
in mageia package for 2.89), possible segfault and caching.");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.90~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-utils", rpm:"dnsmasq-utils~2.90~1.mga9", rls:"MAGEIA9"))) {
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
