# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0076");
  script_cve_id("CVE-2025-25472", "CVE-2025-25474", "CVE-2025-25475");
  script_tag(name:"creation_date", value:"2025-02-26 04:08:53 +0000 (Wed, 26 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0076)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0076");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0076.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34043");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/VEIE5K5WMSCBUU2JDXY5E576NA36I3NC/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcmtk' package(s) announced via the MGASA-2025-0076 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow in DCMTK allows attackers to cause a Denial of Service
(DoS) via a crafted DCM file (CVE-2025-25472).
DCMTK was discovered to contain a buffer overflow via the component
/dcmimgle/diinpxt.h (CVE-2025-25474).
A NULL pointer dereference in the component /libsrc/dcrleccd.cc of DCMTK
allows attackers to cause a Denial of Service (DoS) via a crafted DICOM
file (CVE-2025-25475).");

  script_tag(name:"affected", value:"'dcmtk' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"dcmtk", rpm:"dcmtk~3.6.7~4.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dcmtk-devel", rpm:"lib64dcmtk-devel~3.6.7~4.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dcmtk17", rpm:"lib64dcmtk17~3.6.7~4.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk-devel", rpm:"libdcmtk-devel~3.6.7~4.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk17", rpm:"libdcmtk17~3.6.7~4.4.mga9", rls:"MAGEIA9"))) {
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
