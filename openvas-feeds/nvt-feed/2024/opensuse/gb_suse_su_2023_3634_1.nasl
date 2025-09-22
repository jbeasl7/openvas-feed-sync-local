# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833258");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-4863");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-18 17:48:44 +0000 (Mon, 18 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:23:55 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for libwebp (SUSE-SU-2023:3634-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3634-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RKCQYEPZ6OHEYTCKST3ZQVR4FZO4AJAS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwebp'
  package(s) announced via the SUSE-SU-2023:3634-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libwebp fixes the following issues:

  * CVE-2023-4863: Fixed heap buffer overflow (bsc#1215231).

  ##");

  script_tag(name:"affected", value:"'libwebp' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libwebp7", rpm:"libwebp7~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-debuginfo", rpm:"libwebpdecoder3-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3", rpm:"libwebpmux3~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-debuginfo", rpm:"libwebpmux3-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools-debuginfo", rpm:"libwebp-tools-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2", rpm:"libwebpdemux2~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools", rpm:"libwebp-tools~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel", rpm:"libwebp-devel~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-debuginfo", rpm:"libwebp7-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3", rpm:"libwebpdecoder3~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-debuginfo", rpm:"libwebpdemux2-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-debugsource", rpm:"libwebp-debugsource~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-32bit", rpm:"libwebp7-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-32bit", rpm:"libwebpdemux2-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-32bit-debuginfo", rpm:"libwebpdemux2-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-32bit-debuginfo", rpm:"libwebpdecoder3-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-32bit", rpm:"libwebpmux3-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-32bit-debuginfo", rpm:"libwebp7-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel-32bit", rpm:"libwebp-devel-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-32bit", rpm:"libwebpdecoder3-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-32bit-debuginfo", rpm:"libwebpmux3-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7", rpm:"libwebp7~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-debuginfo", rpm:"libwebpdecoder3-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3", rpm:"libwebpmux3~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-debuginfo", rpm:"libwebpmux3-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools-debuginfo", rpm:"libwebp-tools-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2", rpm:"libwebpdemux2~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools", rpm:"libwebp-tools~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel", rpm:"libwebp-devel~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-debuginfo", rpm:"libwebp7-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3", rpm:"libwebpdecoder3~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-debuginfo", rpm:"libwebpdemux2-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-debugsource", rpm:"libwebp-debugsource~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-32bit", rpm:"libwebp7-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-32bit", rpm:"libwebpdemux2-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-32bit-debuginfo", rpm:"libwebpdemux2-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-32bit-debuginfo", rpm:"libwebpdecoder3-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-32bit", rpm:"libwebpmux3-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-32bit-debuginfo", rpm:"libwebp7-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel-32bit", rpm:"libwebp-devel-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-32bit", rpm:"libwebpdecoder3-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-32bit-debuginfo", rpm:"libwebpmux3-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libwebp7", rpm:"libwebp7~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-debuginfo", rpm:"libwebpdecoder3-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3", rpm:"libwebpmux3~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-debuginfo", rpm:"libwebpmux3-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools-debuginfo", rpm:"libwebp-tools-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2", rpm:"libwebpdemux2~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools", rpm:"libwebp-tools~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel", rpm:"libwebp-devel~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-debuginfo", rpm:"libwebp7-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3", rpm:"libwebpdecoder3~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-debuginfo", rpm:"libwebpdemux2-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-debugsource", rpm:"libwebp-debugsource~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-32bit", rpm:"libwebp7-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-32bit", rpm:"libwebpdemux2-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-32bit-debuginfo", rpm:"libwebpdemux2-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-32bit-debuginfo", rpm:"libwebpdecoder3-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-32bit", rpm:"libwebpmux3-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-32bit-debuginfo", rpm:"libwebp7-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel-32bit", rpm:"libwebp-devel-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-32bit", rpm:"libwebpdecoder3-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-32bit-debuginfo", rpm:"libwebpmux3-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7", rpm:"libwebp7~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-debuginfo", rpm:"libwebpdecoder3-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3", rpm:"libwebpmux3~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-debuginfo", rpm:"libwebpmux3-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools-debuginfo", rpm:"libwebp-tools-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2", rpm:"libwebpdemux2~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools", rpm:"libwebp-tools~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel", rpm:"libwebp-devel~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-debuginfo", rpm:"libwebp7-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3", rpm:"libwebpdecoder3~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-debuginfo", rpm:"libwebpdemux2-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-debugsource", rpm:"libwebp-debugsource~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-32bit", rpm:"libwebp7-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-32bit", rpm:"libwebpdemux2-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux2-32bit-debuginfo", rpm:"libwebpdemux2-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-32bit-debuginfo", rpm:"libwebpdecoder3-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-32bit", rpm:"libwebpmux3-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp7-32bit-debuginfo", rpm:"libwebp7-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel-32bit", rpm:"libwebp-devel-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder3-32bit", rpm:"libwebpdecoder3-32bit~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux3-32bit-debuginfo", rpm:"libwebpmux3-32bit-debuginfo~1.0.3~150200.3.10.1", rls:"openSUSELeap15.5"))) {
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