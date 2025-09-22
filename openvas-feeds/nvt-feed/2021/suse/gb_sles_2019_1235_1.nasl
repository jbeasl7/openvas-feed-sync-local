# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1235.1");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-31 16:11:41 +0000 (Fri, 31 May 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1235-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1235-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191235-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111331");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-May/005459.html");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7023736");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2019:1235-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

This update contains the Intel QSR 2019.1 Microcode release (bsc#1111331)

Four new speculative execution information leak issues have been identified in Intel CPUs. (bsc#1111331)

- CVE-2018-12126: Microarchitectural Store Buffer Data Sampling (MSBDS)
- CVE-2018-12127: Microarchitectural Fill Buffer Data Sampling (MFBDS)
- CVE-2018-12130: Microarchitectural Load Port Data Samling (MLPDS)
- CVE-2019-11091: Microarchitectural Data Sampling Uncacheable Memory (MDSUM)

These updates contain the CPU Microcode adjustments for the software mitigations.

For more information on this set of vulnerabilities, check out [link moved to references]

Release notes:

- Processor Identifier Version Products
- Model Stepping F-MO-S/PI Old->New
- ---- new platforms ----------------------------------------
- CLX-SP B1 6-55-7/bf 05000021 Xeon Scalable Gen2
- ---- updated platforms ------------------------------------
- SNB D2/G1/Q0 6-2a-7/12 0000002e->0000002f Core Gen2
- IVB E1/L1 6-3a-9/12 00000020->00000021 Core Gen3
- HSW C0 6-3c-3/32 00000025->00000027 Core Gen4
- BDW-U/Y E0/F0 6-3d-4/c0 0000002b->0000002d Core Gen5
- IVB-E/EP C1/M1/S1 6-3e-4/ed 0000042e->0000042f Core Gen3 X Series, Xeon E5 v2
- IVB-EX D1 6-3e-7/ed 00000714->00000715 Xeon E7 v2
- HSX-E/EP Cx/M1 6-3f-2/6f 00000041->00000043 Core Gen4 X series, Xeon E5 v3
- HSX-EX E0 6-3f-4/80 00000013->00000014 Xeon E7 v3
- HSW-U C0/D0 6-45-1/72 00000024->00000025 Core Gen4
- HSW-H C0 6-46-1/32 0000001a->0000001b Core Gen4
- BDW-H/E3 E0/G0 6-47-1/22 0000001e->00000020 Core Gen5
- SKL-U/Y D0/K1 6-4e-3/c0 000000c6->000000cc Core Gen6
- SKX-SP H0/M0/U0 6-55-4/b7 0200005a->0000005e Xeon Scalable
- SKX-D M1 6-55-4/b7 0200005a->0000005e Xeon D-21xx
- BDX-DE V1 6-56-2/10 00000019->0000001a Xeon D-1520/40
- BDX-DE V2/3 6-56-3/10 07000016->07000017 Xeon D-1518/19/21/27/28/31/33/37/41/48, Pentium D1507/08/09/17/19
- BDX-DE Y0 6-56-4/10 0f000014->0f000015 Xeon D-1557/59/67/71/77/81/87
- BDX-NS A0 6-56-5/10 0e00000c->0e00000d Xeon D-1513N/23/33/43/53
- APL D0 6-5c-9/03 00000036->00000038 Pentium N/J4xxx, Celeron N/J3xxx, Atom x5/7-E39xx
- SKL-H/S R0/N0 6-5e-3/36 000000c6->000000cc Core Gen6, Xeon E3 v5
- DNV B0 6-5f-1/01 00000024->0000002e Atom Processor C Series
- GLK B0 6-7a-1/01 0000002c->0000002e Pentium Silver N/J5xxx, Celeron N/J4xxx
- AML-Y22 H0 6-8e-9/10 0000009e->000000b4 Core Gen8 Mobile
- KBL-U/Y H0 6-8e-9/c0 0000009a->000000b4 Core Gen7 Mobile
- CFL-U43e D0 6-8e-a/c0 0000009e->000000b4 Core Gen8 Mobile
- WHL-U W0 6-8e-b/d0 000000a4->000000b8 Core Gen8 Mobile
- WHL-U V0 6-8e-d/94 000000b2->000000b8 Core Gen8 Mobile
- KBL-G/H/S/E3 B0 6-9e-9/2a 0000009a->000000b4 Core Gen7, Xeon E3 v6
- CFL-H/S/E3 U0 6-9e-a/22 000000aa->000000b4 Core Gen8 Desktop, Mobile, Xeon E
- CFL-S B0 6-9e-b/02 000000aa->000000b4 Core Gen8
- CFL-H/S P0 6-9e-c/22 000000a2->000000ae Core Gen9");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20190507~13.41.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20190507~13.41.1", rls:"SLES12.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20190507~13.41.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20190507~13.41.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20190507~13.41.1", rls:"SLES12.0SP4"))) {
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
