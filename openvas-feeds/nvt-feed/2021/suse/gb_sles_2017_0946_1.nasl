# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0946.1");
  script_cve_id("CVE-2016-10251", "CVE-2016-8654", "CVE-2016-9395", "CVE-2016-9398", "CVE-2016-9560", "CVE-2016-9583", "CVE-2016-9591", "CVE-2016-9600", "CVE-2017-5498", "CVE-2017-6850");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 20:44:24 +0000 (Tue, 09 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0946-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0946-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170946-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029497");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-April/002785.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper' package(s) announced via the SUSE-SU-2017:0946-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jasper fixes the following issues:

Security issues fixed:
- CVE-2016-8654: Heap-based buffer overflow in QMFB code in JPC codec (bsc#1012530)
- CVE-2016-9395: Missing sanity checks on the data in a SIZ marker segment (bsc#1010977).
- CVE-2016-9398: jpc_math.c:94: int jpc_floorlog2(int): Assertion 'x > 0' failed. (bsc#1010979)
- CVE-2016-9560: stack-based buffer overflow in jpc_tsfb_getbands2 (jpc_tsfb.c) (bsc#1011830)
- CVE-2016-9583: Out of bounds heap read in jpc_pi_nextpcrl() (bsc#1015400)
- CVE-2016-9591: Use-after-free on heap in jas_matrix_destroy (bsc#1015993)
- CVE-2016-9600: Null Pointer Dereference due to missing check for UNKNOWN color space in JP2 encoder (bsc#1018088)
- CVE-2016-10251: Use of uninitialized value in jpc_pi_nextcprl (jpc_t2cod.c) (bsc#1029497)
- CVE-2017-5498: left-shift undefined behaviour (bsc#1020353)
- CVE-2017-6850: NULL pointer dereference in jp2_cdef_destroy (jp2_cod.c) (bsc#1021868)");

  script_tag(name:"affected", value:"'jasper' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libjasper", rpm:"libjasper~1.900.14~134.32.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper-32bit", rpm:"libjasper-32bit~1.900.14~134.32.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper-x86", rpm:"libjasper-x86~1.900.14~134.32.1", rls:"SLES11.0SP4"))) {
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
