# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0298");
  script_cve_id("CVE-2023-47016");
  script_tag(name:"creation_date", value:"2024-09-16 04:11:26 +0000 (Mon, 16 Sep 2024)");
  script_version("2024-09-16T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-16 05:05:46 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-29 18:03:48 +0000 (Wed, 29 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0298)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0298");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0298.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33534");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZIWVQC4JNA2JCJ7L3XNZBGYJ52KSQWKC/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'radare2' package(s) announced via the MGASA-2024-0298 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"radare2 has an out-of-bounds read in r_bin_object_set_items in
libr/bin/bobj.c, causing a crash in r_read_le32 in libr/include/r_endian");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64radare2-devel", rpm:"lib64radare2-devel~5.8.8~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radare2_5.8.8", rpm:"lib64radare2_5.8.8~5.8.8~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradare2-devel", rpm:"libradare2-devel~5.8.8~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradare2_5.8.8", rpm:"libradare2_5.8.8~5.8.8~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2", rpm:"radare2~5.8.8~1.2.mga9", rls:"MAGEIA9"))) {
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
