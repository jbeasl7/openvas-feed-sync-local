# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0246");
  script_cve_id("CVE-2022-4285", "CVE-2023-1972", "CVE-2023-39128", "CVE-2023-39129", "CVE-2023-39130");
  script_tag(name:"creation_date", value:"2024-07-02 04:11:44 +0000 (Tue, 02 Jul 2024)");
  script_version("2024-07-02T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-02 05:05:43 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-25 17:26:20 +0000 (Thu, 25 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0246)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0246");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0246.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33319");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6842-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb' package(s) announced via the MGASA-2024-0246 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An illegal memory access flaw was found in the binutils package. Parsing
an ELF file containing corrupt symbol version information may result in
a denial of service. This issue is the result of an incomplete fix for
CVE-2020-16599. (CVE-2022-4285)
A potential heap based buffer overflow was found in
_bfd_elf_slurp_version_tables() in bfd/elf.c. This may lead to loss of
availability. (CVE-2023-1972)
GNU gdb (GDB) 13.0.50.20220805-git was discovered to contain a stack
overflow via the function ada_decode at /gdb/ada-lang.c.
(CVE-2023-39128)
GNU gdb (GDB) 13.0.50.20220805-git was discovered to contain a heap use
after free via the function add_pe_exported_sym() at
/gdb/coff-pe-read.c. (CVE-2023-39129)
GNU gdb (GDB) 13.0.50.20220805-git was discovered to contain a heap
buffer overflow via the function pe_as16() at /gdb/coff-pe-read.c.
(CVE-2023-39130)");

  script_tag(name:"affected", value:"'gdb' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~12.1~7.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-doc", rpm:"gdb-doc~12.1~7.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-gdbserver", rpm:"gdb-gdbserver~12.1~7.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-headless", rpm:"gdb-headless~12.1~7.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-minimal", rpm:"gdb-minimal~12.1~7.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"urpmi-debuginfo-install", rpm:"urpmi-debuginfo-install~12.1~7.1.mga9", rls:"MAGEIA9"))) {
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
