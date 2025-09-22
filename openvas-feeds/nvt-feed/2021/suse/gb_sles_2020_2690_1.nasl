# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2690.1");
  script_cve_id("CVE-2016-9397", "CVE-2016-9398", "CVE-2016-9399", "CVE-2016-9557", "CVE-2017-14132", "CVE-2017-5499", "CVE-2017-5503", "CVE-2017-5504", "CVE-2017-5505", "CVE-2017-9782", "CVE-2018-18873", "CVE-2018-19139", "CVE-2018-19543", "CVE-2018-20570", "CVE-2018-20622", "CVE-2018-9154", "CVE-2018-9252");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-07 18:40:45 +0000 (Fri, 07 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2690-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2690-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202690-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120807");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-September/007443.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper' package(s) announced via the SUSE-SU-2020:2690-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jasper fixes the following issues:

- CVE-2016-9398: Improved patch for already fixed issue (bsc#1010979).
- CVE-2016-9399: Fix assert in calcstepsizes (bsc#1010980).
- CVE-2016-9397: Fix assert in jpc_dequantize (bsc#1010786).
- CVE-2016-9557: Fix signed integer overflow (bsc#1011829).
- CVE-2017-5499: Validate component depth bit (bsc#1020451).
- CVE-2017-5503: Check bounds in jas_seq2d_bindsub() (bsc#1020456).
- CVE-2017-5504: Check bounds in jas_seq2d_bindsub() (bsc#1020458).
- CVE-2017-5505: Check bounds in jas_seq2d_bindsub() (bsc#1020460).
- CVE-2017-14132: Fix heap base overflow in by checking components (bsc#1057152).
- CVE-2018-9154: Fixed a potential denial of service in jpc_dec_process_sot() (bsc#1092115).
- CVE-2018-9252: Fix reachable assertion in jpc_abstorelstepsize (bsc#1088278).
- CVE-2018-18873: Fix null pointer deref in ras_putdatastd (bsc#1114498).
- CVE-2018-19139: Fix mem leaks by registering jpc_unk_destroyparms (bsc#1115637).
- CVE-2018-19543, bsc#1045450 CVE-2017-9782: Fix numchans mixup (bsc#1117328).
- CVE-2018-20570: Fix heap based buffer over-read in jp2_encode (bsc#1120807).
- CVE-2018-20622: Fix memory leak in jas_malloc.c (bsc#1120805).");

  script_tag(name:"affected", value:"'jasper' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libjasper1", rpm:"libjasper1~1.900.14~195.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper1-32bit", rpm:"libjasper1-32bit~1.900.14~195.22.1", rls:"SLES12.0SP5"))) {
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
