# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2775.1");
  script_cve_id("CVE-2008-3522", "CVE-2014-8158", "CVE-2015-5203", "CVE-2015-5221", "CVE-2016-1577", "CVE-2016-1867", "CVE-2016-2089", "CVE-2016-2116", "CVE-2016-8690", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8880", "CVE-2016-8881", "CVE-2016-8882", "CVE-2016-8883", "CVE-2016-8884", "CVE-2016-8885", "CVE-2016-8886", "CVE-2016-8887");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-27 15:35:30 +0000 (Mon, 27 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2775-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2775-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162775-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/392410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968373");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002398.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper' package(s) announced via the SUSE-SU-2016:2775-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for jasper to version 1.900.14 fixes several issues.

These security issues were fixed:
- CVE-2016-8887: NULL pointer dereference in jp2_colr_destroy (jp2_cod.c) (bsc#1006836)
- CVE-2016-8886: memory allocation failure in jas_malloc (jas_malloc.c) (bsc#1006599)
- CVE-2016-8884,CVE-2016-8885: two null pointer dereferences in bmp_getdata (incomplete fix for CVE-2016-8690) (bsc#1007009)
- CVE-2016-8883: assert in jpc_dec_tiledecode() (bsc#1006598)
- CVE-2016-8882: segfault / null pointer access in jpc_pi_destroy (bsc#1006597)
- CVE-2016-8881: Heap overflow in jpc_getuint16() (bsc#1006593)
- CVE-2016-8880: Heap overflow in jpc_dec_cp_setfromcox() (bsc#1006591)
- CVE-2016-8693 Double free vulnerability in mem_close (bsc#1005242)
- CVE-2016-8691, CVE-2016-8692: Divide by zero in jpc_dec_process_siz (bsc#1005090)
- CVE-2016-8690: Null pointer dereference in bmp_getdata triggered by crafted BMP image (bsc#1005084)
- CVE-2016-2116: Memory leak in the jas_iccprof_createfrombuf function in JasPer allowed remote attackers to cause a denial of service (memory consumption) via a crafted ICC color profile in a JPEG 2000 image file (bsc#968373)
- CVE-2016-2089: invalid read in the JasPer's jas_matrix_clip() function (bsc#963983)
- CVE-2016-1867: Out-of-bounds Read in the JasPer's jpc_pi_nextcprl() function (bsc#961886)
- CVE-2015-5221: Use-after-free (and double-free) in Jasper JPEG-200 (bsc#942553).
- CVE-2015-5203: Double free corruption in JasPer JPEG-2000 implementation (bsc#941919)
- CVE-2008-3522: Buffer overflow in the jas_stream_printf function in libjasper/base/jas_stream.c in JasPer might have allowed context-dependent attackers to have an unknown impact via vectors related to the mif_hdr_put function and use of vsprintf (bsc#392410)
- jasper: NULL pointer dereference in jp2_colr_destroy (jp2_cod.c) (incomplete fix for CVE-2016-8887) (bsc#1006839)

For additional change description please have a look at the changelog.");

  script_tag(name:"affected", value:"'jasper' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libjasper1", rpm:"libjasper1~1.900.14~181.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper1-32bit", rpm:"libjasper1-32bit~1.900.14~181.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libjasper1", rpm:"libjasper1~1.900.14~181.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjasper1-32bit", rpm:"libjasper1-32bit~1.900.14~181.1", rls:"SLES12.0SP2"))) {
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
