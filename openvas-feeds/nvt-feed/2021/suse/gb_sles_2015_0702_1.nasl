# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0702.1");
  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0702-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0702-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150702-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921978");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-April/001343.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libXfont' package(s) announced via the SUSE-SU-2015:0702-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LibXFont was updated to fix security problems.

Following security issues were fixed:
- CVE-2015-1802: The bdf parser reads a count for the number of properties
 defined in a font from the font file, and allocates arrays with entries for each
 property based on that count. It never checked to see if that count
 was negative, or large enough to overflow when multiplied by the size
 of the structures being allocated, and could thus allocate the wrong
 buffer size, leading to out of bounds writes.

- CVE-2015-1803: If the bdf parser failed to parse the data for the bitmap for any
 character, it would proceed with an invalid pointer to the bitmap
 data and later crash when trying to read the bitmap from that pointer.

- CVE-2015-1804: The bdf parser read metrics values as 32-bit integers, but stored
 them into 16-bit integers. Overflows could occur in various operations
 leading to out-of-bounds memory access.");

  script_tag(name:"affected", value:"'libXfont' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libXfont1", rpm:"libXfont1~1.4.7~4.1", rls:"SLES12.0"))) {
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
