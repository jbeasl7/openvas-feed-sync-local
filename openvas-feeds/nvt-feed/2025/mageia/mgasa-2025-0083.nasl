# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0083");
  script_cve_id("CVE-2025-1378");
  script_tag(name:"creation_date", value:"2025-03-03 04:09:02 +0000 (Mon, 03 Mar 2025)");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-17 06:15:13 +0000 (Mon, 17 Feb 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0083)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0083");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0083.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34044");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/6L3CRKPOLSYHPHW4QETC25D65CTE33EO/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'radare2' package(s) announced via the MGASA-2025-0083 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability, which was classified as problematic, was found in
radare2. Affected is an unknown function in the library
/libr/main/rasm2.c of the component rasm2. The manipulation leads to
memory corruption. An attack has to be approached locally. The exploit
has been disclosed to the public and may be used.");

  script_tag(name:"affected", value:"'radare2' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64radare2-devel", rpm:"lib64radare2-devel~5.8.8~1.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radare2_5.8.8", rpm:"lib64radare2_5.8.8~5.8.8~1.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradare2-devel", rpm:"libradare2-devel~5.8.8~1.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradare2_5.8.8", rpm:"libradare2_5.8.8~5.8.8~1.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2", rpm:"radare2~5.8.8~1.5.mga9", rls:"MAGEIA9"))) {
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
