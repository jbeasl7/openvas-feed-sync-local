# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0111");
  script_cve_id("CVE-2024-1580");
  script_tag(name:"creation_date", value:"2024-04-09 04:13:31 +0000 (Tue, 09 Apr 2024)");
  script_version("2025-01-24T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-24 05:37:33 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-23 16:48:27 +0000 (Thu, 23 Jan 2025)");

  script_name("Mageia: Security Advisory (MGASA-2024-0111)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0111");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0111.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33014");
  script_xref(name:"URL", value:"https://lwn.net/Articles/966589/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dav1d' package(s) announced via the MGASA-2024-0111 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow in dav1d AV1 decoder that can occur when decoding
videos with large frame size. This can lead to memory corruption within
the AV1 decoder. (CVE-2024-1580)");

  script_tag(name:"affected", value:"'dav1d' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"dav1d", rpm:"dav1d~1.2.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dav1d-devel", rpm:"lib64dav1d-devel~1.2.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dav1d6", rpm:"lib64dav1d6~1.2.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdav1d-devel", rpm:"libdav1d-devel~1.2.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdav1d6", rpm:"libdav1d6~1.2.1~1.1.mga9", rls:"MAGEIA9"))) {
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
