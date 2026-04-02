# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0076");
  script_cve_id("CVE-2026-27171");
  script_tag(name:"creation_date", value:"2026-04-01 05:01:04 +0000 (Wed, 01 Apr 2026)");
  script_version("2026-04-01T06:13:16+0000");
  script_tag(name:"last_modification", value:"2026-04-01 06:13:16 +0000 (Wed, 01 Apr 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-20 16:45:28 +0000 (Fri, 20 Feb 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0076)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0076");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0076.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35291");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2440530");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2026-27171");
  script_xref(name:"URL", value:"https://ubuntu.com/security/CVE-2026-27171");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zlib' package(s) announced via the MGASA-2026-0076 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"zlib before 1.3.2 allows CPU consumption via crc32_combine64 and
crc32_combine_gen64 because x2nmodp can do right shifts within a loop
that has no termination condition. (CVE-2026-27171)");

  script_tag(name:"affected", value:"'zlib' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64minizip-devel", rpm:"lib64minizip-devel~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64minizip1", rpm:"lib64minizip1~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib-devel", rpm:"lib64zlib-devel~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib-static-devel", rpm:"lib64zlib-static-devel~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zlib1", rpm:"lib64zlib1~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip-devel", rpm:"libminizip-devel~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1", rpm:"libminizip1~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib-devel", rpm:"libzlib-devel~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib-static-devel", rpm:"libzlib-static-devel~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzlib1", rpm:"libzlib1~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib", rpm:"zlib~1.2.13~1.4.mga9", rls:"MAGEIA9"))) {
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
