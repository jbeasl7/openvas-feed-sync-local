# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0072");
  script_cve_id("CVE-2026-25075");
  script_tag(name:"creation_date", value:"2026-03-30 05:00:13 +0000 (Mon, 30 Mar 2026)");
  script_version("2026-03-30T06:15:36+0000");
  script_tag(name:"last_modification", value:"2026-03-30 06:15:36 +0000 (Mon, 30 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-23 19:16:39 +0000 (Mon, 23 Mar 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0072)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0072");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0072.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35265");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2026/msg00085.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/WWO45DS2P5I7KBXXZSDAS4ECX6DR3NYJ/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8117-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan' package(s) announced via the MGASA-2026-0072 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"strongSwan 4.5.0 < 6.0.5 EAP-TTLS AVP Parsing Integer Underflow.
(CVE-2026-25075)");

  script_tag(name:"affected", value:"'strongswan' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64strongswan0", rpm:"lib64strongswan0~5.9.14~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstrongswan0", rpm:"libstrongswan0~5.9.14~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~5.9.14~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-charon-nm", rpm:"strongswan-charon-nm~5.9.14~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-tnc-imcvs", rpm:"strongswan-tnc-imcvs~5.9.14~1.2.mga9", rls:"MAGEIA9"))) {
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
