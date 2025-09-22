# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3170.1");
  script_cve_id("CVE-2014-9939", "CVE-2017-12448", "CVE-2017-12450", "CVE-2017-12452", "CVE-2017-12453", "CVE-2017-12454", "CVE-2017-12456", "CVE-2017-12799", "CVE-2017-13757", "CVE-2017-14128", "CVE-2017-14129", "CVE-2017-14130", "CVE-2017-14333", "CVE-2017-14529", "CVE-2017-14729", "CVE-2017-14745", "CVE-2017-14974", "CVE-2017-6965", "CVE-2017-6966", "CVE-2017-6969", "CVE-2017-7209", "CVE-2017-7210", "CVE-2017-7223", "CVE-2017-7224", "CVE-2017-7225", "CVE-2017-7226", "CVE-2017-7227", "CVE-2017-7299", "CVE-2017-7300", "CVE-2017-7301", "CVE-2017-7302", "CVE-2017-7303", "CVE-2017-7304", "CVE-2017-7614", "CVE-2017-8392", "CVE-2017-8393", "CVE-2017-8394", "CVE-2017-8395", "CVE-2017-8396", "CVE-2017-8397", "CVE-2017-8398", "CVE-2017-8421", "CVE-2017-9038", "CVE-2017-9039", "CVE-2017-9040", "CVE-2017-9041", "CVE-2017-9042", "CVE-2017-9043", "CVE-2017-9044", "CVE-2017-9746", "CVE-2017-9747", "CVE-2017-9748", "CVE-2017-9750", "CVE-2017-9755", "CVE-2017-9756", "CVE-2017-9954", "CVE-2017-9955");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-13 14:01:29 +0000 (Thu, 13 Apr 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3170-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3170-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173170-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/437293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/445037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/546106");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/561142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/578249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/590820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/698346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/713504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/776968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970239");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-November/003462.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the SUSE-SU-2017:3170-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNU binutil was updated to the 2.29.1 release, bringing various new features, fixing a lot of bugs and security issues.

Following security issues are being addressed by this release:

 * 18750 bsc#1030296 CVE-2014-9939
 * 20891 bsc#1030585 CVE-2017-7225
 * 20892 bsc#1030588 CVE-2017-7224
 * 20898 bsc#1030589 CVE-2017-7223
 * 20905 bsc#1030584 CVE-2017-7226
 * 20908 bsc#1031644 CVE-2017-7299
 * 20909 bsc#1031656 CVE-2017-7300
 * 20921 bsc#1031595 CVE-2017-7302
 * 20922 bsc#1031593 CVE-2017-7303
 * 20924 bsc#1031638 CVE-2017-7301
 * 20931 bsc#1031590 CVE-2017-7304
 * 21135 bsc#1030298 CVE-2017-7209
 * 21137 bsc#1029909 CVE-2017-6965
 * 21139 bsc#1029908 CVE-2017-6966
 * 21156 bsc#1029907 CVE-2017-6969
 * 21157 bsc#1030297 CVE-2017-7210
 * 21409 bsc#1037052 CVE-2017-8392
 * 21412 bsc#1037057 CVE-2017-8393
 * 21414 bsc#1037061 CVE-2017-8394
 * 21432 bsc#1037066 CVE-2017-8396
 * 21440 bsc#1037273 CVE-2017-8421
 * 21580 bsc#1044891 CVE-2017-9746
 * 21581 bsc#1044897 CVE-2017-9747
 * 21582 bsc#1044901 CVE-2017-9748
 * 21587 bsc#1044909 CVE-2017-9750
 * 21594 bsc#1044925 CVE-2017-9755
 * 21595 bsc#1044927 CVE-2017-9756
 * 21787 bsc#1052518 CVE-2017-12448
 * 21813 bsc#1052503, CVE-2017-12456, bsc#1052507, CVE-2017-12454, bsc#1052509, CVE-2017-12453, bsc#1052511, CVE-2017-12452, bsc#1052514, CVE-2017-12450, bsc#1052503, CVE-2017-12456, bsc#1052507, CVE-2017-12454, bsc#1052509, CVE-2017-12453, bsc#1052511, CVE-2017-12452, bsc#1052514, CVE-2017-12450
 * 21933 bsc#1053347 CVE-2017-12799
 * 21990 bsc#1058480 CVE-2017-14333
 * 22018 bsc#1056312 CVE-2017-13757
 * 22047 bsc#1057144 CVE-2017-14129
 * 22058 bsc#1057149 CVE-2017-14130
 * 22059 bsc#1057139 CVE-2017-14128
 * 22113 bsc#1059050 CVE-2017-14529
 * 22148 bsc#1060599 CVE-2017-14745
 * 22163 bsc#1061241 CVE-2017-14974
 * 22170 bsc#1060621 CVE-2017-14729

Update to binutils 2.29. [fate#321454, fate#321494, fate#323293]:

 * The MIPS port now supports microMIPS eXtended Physical Addressing (XPA)
 instructions for assembly and disassembly.
 * The MIPS port now supports the microMIPS Release 5 ISA for assembly and
 disassembly.
 * The MIPS port now supports the Imagination interAptiv MR2 processor,
 which implements the MIPS32r3 ISA, the MIPS16e2 ASE as well as a couple
 of implementation-specific regular MIPS and MIPS16e2 ASE instructions.
 * The SPARC port now supports the SPARC M8 processor, which implements the
 Oracle SPARC Architecture 2017.
 * The MIPS port now supports the MIPS16e2 ASE for assembly and disassembly.
 * Add support for ELF SHF_GNU_MBIND and PT_GNU_MBIND_XXX.
 * Add support for the wasm32 ELF conversion of the WebAssembly file format.
 * Add --inlines option to objdump, which extends the --line-numbers option
 so that inlined functions will display their nesting information.
 * Add --merge-notes options to objcopy to reduce the size of notes in
 a binary file by merging and deleting redundant notes.
 * Add support ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.29.1~9.20.2", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.29.1~9.20.2", rls:"SLES12.0SP3"))) {
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
