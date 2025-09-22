# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1236.1");
  script_cve_id("CVE-2017-7585", "CVE-2017-7741", "CVE-2017-7742", "CVE-2017-8361", "CVE-2017-8362", "CVE-2017-8363", "CVE-2017-8365");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-30 19:59:00 +0000 (Sun, 30 Apr 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1236-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171236-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036946");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002854.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsndfile' package(s) announced via the SUSE-SU-2017:1236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsndfile fixes the following issues:

- CVE-2017-8362: invalid memory read in flac_buffer_copy (flac.c) (bsc#1036943)
- CVE-2017-8365: global buffer overflow in i2les_array (pcm.c) (bsc#1036946)
- CVE-2017-8361: global buffer overflow in flac_buffer_copy (flac.c) (bsc#1036944)
- CVE-2017-8363: heap-based buffer overflow in flac_buffer_copy (flac.c) (bsc#1036945)
- CVE-2017-7585: stack-based buffer overflow via a specially crafted FLAC file (bsc#1033054)");

  script_tag(name:"affected", value:"'libsndfile' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libsndfile", rpm:"libsndfile~1.0.20~2.18.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile-32bit", rpm:"libsndfile-32bit~1.0.20~2.18.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile-x86", rpm:"libsndfile-x86~1.0.20~2.18.1", rls:"SLES11.0SP4"))) {
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
