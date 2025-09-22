# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2615.1");
  script_cve_id("CVE-2018-13139", "CVE-2018-19432", "CVE-2018-19758", "CVE-2021-3246");
  script_tag(name:"creation_date", value:"2021-08-05 14:33:38 +0000 (Thu, 05 Aug 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-29 13:43:02 +0000 (Thu, 29 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2615-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2615-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212615-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188540");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-August/009252.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsndfile' package(s) announced via the SUSE-SU-2021:2615-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsndfile fixes the following issues:

- CVE-2018-13139: Fixed a stack-based buffer overflow in psf_memset in common.c in libsndfile 1.0.28allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact. (bsc#1100167)
- CVE-2018-19432: Fixed a NULL pointer dereference in the function sf_write_int in sndfile.c, which will lead to a denial of service. (bsc#1116993)
- CVE-2021-3246: Fixed a heap buffer overflow vulnerability in msadpcm_decode_block. (bsc#1188540)
- CVE-2018-19758: Fixed a heap-based buffer over-read at wav.c in wav_write_header in libsndfile 1.0.28 that will cause a denial of service. (bsc#1117954)");

  script_tag(name:"affected", value:"'libsndfile' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1", rpm:"libsndfile1~1.0.25~36.23.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1-32bit", rpm:"libsndfile1-32bit~1.0.25~36.23.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1", rpm:"libsndfile1~1.0.25~36.23.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1-32bit", rpm:"libsndfile1-32bit~1.0.25~36.23.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1", rpm:"libsndfile1~1.0.25~36.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1-32bit", rpm:"libsndfile1-32bit~1.0.25~36.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1", rpm:"libsndfile1~1.0.25~36.23.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1-32bit", rpm:"libsndfile1-32bit~1.0.25~36.23.1", rls:"SLES12.0SP5"))) {
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
