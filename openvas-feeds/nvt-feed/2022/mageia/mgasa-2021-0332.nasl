# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0332");
  script_cve_id("CVE-2021-20308", "CVE-2021-23158", "CVE-2021-23165", "CVE-2021-23180", "CVE-2021-23191", "CVE-2021-23206", "CVE-2021-26252", "CVE-2021-26259", "CVE-2021-26948");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 17:01:58 +0000 (Tue, 22 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2021-0332)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0332");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0332.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29101");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29161");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RXMQHLXPNKTCGM4HNTMLHF7NWL3ZXKIO/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4928");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'htmldoc' package(s) announced via the MGASA-2021-0332 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated htmldoc packages fix security vulnerabilities:

Integer overflow in the htmldoc 1.9.11 and before may allow attackers to
execute arbitrary code and cause a denial of service that is similar to
CVE-2017-9181 (CVE-2021-20308).

AddressSanitizer: double-free in function pspdf_export ps-pdf.cxx
(CVE-2021-23158).

AddressSanitizer: heap-buffer-overflow in pspdf_prepare_outpages() in
ps-pdf.cxx (CVE-2021-23165).

AddressSanitizer: SEGV in file_extension file.c (CVE-2021-23180).

AddressSanitizer: SEGV on unknown address 0x000000000014 (CVE-2021-23191).

AddressSanitizer: stack-buffer-overflow in parse_table ps-pdf.cxx
(CVE-2021-23206).

AddressSanitizer: heap-buffer-overflow in pspdf_prepare_page(int)
ps-pdf.cxx (CVE-2021-26252).

AddressSanitizer: heap-buffer-overflow on render_table_row() ps-pdf.cxx
(CVE-2021-26259).

SEGV on unknown address 0x000000000000 (CVE-2021-26948).");

  script_tag(name:"affected", value:"'htmldoc' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"htmldoc", rpm:"htmldoc~1.9.3~2.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"htmldoc-nogui", rpm:"htmldoc-nogui~1.9.3~2.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"htmldoc", rpm:"htmldoc~1.9.8~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"htmldoc-nogui", rpm:"htmldoc-nogui~1.9.8~1.2.mga8", rls:"MAGEIA8"))) {
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
