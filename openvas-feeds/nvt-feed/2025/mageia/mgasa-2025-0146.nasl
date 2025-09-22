# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0146");
  script_cve_id("CVE-2023-53034", "CVE-2025-21955", "CVE-2025-21956", "CVE-2025-21957", "CVE-2025-21959", "CVE-2025-21960", "CVE-2025-21962", "CVE-2025-21963", "CVE-2025-21964", "CVE-2025-21966", "CVE-2025-21967", "CVE-2025-21968", "CVE-2025-21969", "CVE-2025-21970", "CVE-2025-21971", "CVE-2025-21975", "CVE-2025-21978", "CVE-2025-21979", "CVE-2025-21980", "CVE-2025-21981", "CVE-2025-21986", "CVE-2025-21991", "CVE-2025-21992", "CVE-2025-21993", "CVE-2025-21994", "CVE-2025-21995", "CVE-2025-21996", "CVE-2025-21997", "CVE-2025-21999", "CVE-2025-22001", "CVE-2025-22003", "CVE-2025-22004", "CVE-2025-22005", "CVE-2025-22007", "CVE-2025-22008", "CVE-2025-22009", "CVE-2025-22010", "CVE-2025-22013", "CVE-2025-22014", "CVE-2025-22015", "CVE-2025-22018", "CVE-2025-22020", "CVE-2025-22021", "CVE-2025-22025", "CVE-2025-22027", "CVE-2025-22029", "CVE-2025-22033", "CVE-2025-22035", "CVE-2025-22038", "CVE-2025-22040", "CVE-2025-22041", "CVE-2025-22042", "CVE-2025-22043", "CVE-2025-22044", "CVE-2025-22045", "CVE-2025-22047", "CVE-2025-22048", "CVE-2025-22049", "CVE-2025-22050", "CVE-2025-22053", "CVE-2025-22054", "CVE-2025-22055", "CVE-2025-22056", "CVE-2025-22057", "CVE-2025-22058", "CVE-2025-22060", "CVE-2025-22063", "CVE-2025-22064", "CVE-2025-22066", "CVE-2025-22071", "CVE-2025-22072", "CVE-2025-22073", "CVE-2025-22074", "CVE-2025-22075", "CVE-2025-22077", "CVE-2025-22079", "CVE-2025-22080", "CVE-2025-22081", "CVE-2025-22083", "CVE-2025-22086", "CVE-2025-22088", "CVE-2025-22089", "CVE-2025-22090", "CVE-2025-22093", "CVE-2025-22095", "CVE-2025-22097", "CVE-2025-22119", "CVE-2025-23136", "CVE-2025-23138", "CVE-2025-37785", "CVE-2025-37893", "CVE-2025-38152", "CVE-2025-38240", "CVE-2025-38575", "CVE-2025-38637", "CVE-2025-39728", "CVE-2025-39735");
  script_tag(name:"creation_date", value:"2025-05-05 08:07:58 +0000 (Mon, 05 May 2025)");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-29 18:51:14 +0000 (Tue, 29 Apr 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0146)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0146");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0146.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34191");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.80");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.81");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.82");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.83");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.84");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.85");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.86");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.87");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.88");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2025-0146 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vanilla upstream kernel version 6.6.88 fixes bugs and vulnerabilities.
For information about the vulnerabilities see the links.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~6.6.88~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel", rpm:"kernel-linus-devel~6.6.88~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~6.6.88~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~6.6.88~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~6.6.88~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source", rpm:"kernel-linus-source~6.6.88~1.mga9", rls:"MAGEIA9"))) {
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
