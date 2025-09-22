# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0183");
  script_cve_id("CVE-2025-37797", "CVE-2025-37799", "CVE-2025-37800", "CVE-2025-37801", "CVE-2025-37803", "CVE-2025-37804", "CVE-2025-37805", "CVE-2025-37808", "CVE-2025-37810", "CVE-2025-37811", "CVE-2025-37812", "CVE-2025-37813", "CVE-2025-37815", "CVE-2025-37817", "CVE-2025-37818", "CVE-2025-37819", "CVE-2025-37820", "CVE-2025-37823", "CVE-2025-37824", "CVE-2025-37828", "CVE-2025-37829", "CVE-2025-37830", "CVE-2025-37831", "CVE-2025-37836", "CVE-2025-37878", "CVE-2025-37879", "CVE-2025-37881", "CVE-2025-37883", "CVE-2025-37884", "CVE-2025-37885", "CVE-2025-37886", "CVE-2025-37887", "CVE-2025-37890", "CVE-2025-37891", "CVE-2025-37897", "CVE-2025-37901", "CVE-2025-37903", "CVE-2025-37905", "CVE-2025-37909", "CVE-2025-37911", "CVE-2025-37912", "CVE-2025-37913", "CVE-2025-37914", "CVE-2025-37915", "CVE-2025-37916", "CVE-2025-37917", "CVE-2025-37918", "CVE-2025-37921", "CVE-2025-37922", "CVE-2025-37923", "CVE-2025-37924", "CVE-2025-37927", "CVE-2025-37928", "CVE-2025-37929", "CVE-2025-37930", "CVE-2025-37932", "CVE-2025-37933", "CVE-2025-37935", "CVE-2025-37936", "CVE-2025-37938", "CVE-2025-37947", "CVE-2025-37948", "CVE-2025-37949", "CVE-2025-37951", "CVE-2025-37952", "CVE-2025-37953", "CVE-2025-37954", "CVE-2025-37956", "CVE-2025-37959", "CVE-2025-37961", "CVE-2025-37962", "CVE-2025-37963", "CVE-2025-37964", "CVE-2025-37969", "CVE-2025-37970", "CVE-2025-37972", "CVE-2025-37973", "CVE-2025-37983", "CVE-2025-37985", "CVE-2025-37988", "CVE-2025-37989", "CVE-2025-37990", "CVE-2025-37991", "CVE-2025-37992");
  script_tag(name:"creation_date", value:"2025-06-12 04:12:04 +0000 (Thu, 12 Jun 2025)");
  script_version("2025-06-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-06-12 05:40:18 +0000 (Thu, 12 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-05 14:32:13 +0000 (Thu, 05 Jun 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0183)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0183");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0183.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34303");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.89");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.90");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.91");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.92");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.93");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2025-0183 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vanilla upstream kernel version 6.6.93 fixes bugs and vulnerabilities.
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~6.6.93~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel", rpm:"kernel-linus-devel~6.6.93~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~6.6.93~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~6.6.93~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~6.6.93~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source", rpm:"kernel-linus-source~6.6.93~1.mga9", rls:"MAGEIA9"))) {
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
