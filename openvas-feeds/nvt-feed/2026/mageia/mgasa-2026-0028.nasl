# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0028");
  script_cve_id("CVE-2025-67268", "CVE-2025-67269");
  script_tag(name:"creation_date", value:"2026-01-30 04:36:00 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0028)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0028");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0028.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34959");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7948-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gpsd' package(s) announced via the MGASA-2026-0028 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"gpsd before commit dc966aa contains a heap-based out-of-bounds write
vulnerability in the drivers/driver_nmea2000.c file. The hnd_129540
function, which handles NMEA2000 PGN 129540 (GNSS Satellites in View)
packets, fails to validate the user-supplied satellite count against the
size of the skyview array (184 elements). This allows an attacker to
write beyond the bounds of the array by providing a satellite count up
to 255, leading to memory corruption, Denial of Service (DoS), and
potentially arbitrary code execution. (CVE-2025-67268)
An integer underflow vulnerability exists in the `nextstate()` function
in `gpsd/packet.c` of gpsd versions prior to commit
`ffa1d6f40bca0b035fc7f5e563160ebb67199da7`. When parsing a NAVCOM
packet, the payload length is calculated using `lexer->length =
(size_t)c - 4` without checking if the input byte `c` is less than 4.
This results in an unsigned integer underflow, setting `lexer->length`
to a very large value (near `SIZE_MAX`). The parser then enters a loop
attempting to consume this massive number of bytes, causing 100% CPU
utilization and a Denial of Service (DoS) condition. (CVE-2025-67269)");

  script_tag(name:"affected", value:"'gpsd' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gpsd", rpm:"gpsd~3.25~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-clients", rpm:"gpsd-clients~3.25~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64Qgpsmm30", rpm:"lib64Qgpsmm30~3.25~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gpsd-devel", rpm:"lib64gpsd-devel~3.25~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gpsd30", rpm:"lib64gpsd30~3.25~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gpsdpacket30", rpm:"lib64gpsdpacket30~3.25~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQgpsmm30", rpm:"libQgpsmm30~3.25~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpsd-devel", rpm:"libgpsd-devel~3.25~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpsd30", rpm:"libgpsd30~3.25~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpsdpacket30", rpm:"libgpsdpacket30~3.25~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gpsd", rpm:"python3-gpsd~3.25~1.1.mga9", rls:"MAGEIA9"))) {
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
