# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1589.1");
  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:02 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-25 16:52:27 +0000 (Tue, 25 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1589-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1589-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201589-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2020:1589-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

Updated Intel CPU Microcode to 20200602 (prerelease) (bsc#1172466)

This update contains security mitigations for:

CVE-2020-0543: Fixed a side channel attack against special registers
 which could have resulted in leaking of read values to cores other than
 the one which called it. This attack is known as Special Register
 Buffer Data Sampling (SRBDS) or 'CrossTalk' (bsc#1154824).

CVE-2020-0548,CVE-2020-0549: Additional ucode updates were supplied to
 mitigate the Vector Register and L1D Eviction Sampling aka
 'CacheOutAttack' attacks. (bsc#1156353)

Microcode Table:

 Processor Identifier Version Products Model Stepping F-MO-S/PI Old->New
 ---- new platforms ----------------------------------------
 ---- updated platforms ------------------------------------ HSW
 C0 6-3c-3/32 00000027->00000028 Core Gen4 BDW-U/Y E0/F0
 6-3d-4/c0 0000002e->0000002f Core Gen5 HSW-U C0/D0 6-45-1/72
 00000025->00000026 Core Gen4 HSW-H C0 6-46-1/32
 0000001b->0000001c Core Gen4 BDW-H/E3 E0/G0 6-47-1/22
 00000021->00000022 Core Gen5 SKL-U/Y D0 6-4e-3/c0
 000000d6->000000dc Core Gen6 Mobile SKL-U23e K1 6-4e-3/c0
 000000d6->000000dc Core Gen6 Mobile SKX-SP B1 6-55-3/97
 01000151->01000157 Xeon Scalable SKX-SP H0/M0/U0 6-55-4/b7
 02000065->02006906 Xeon Scalable SKX-D M1 6-55-4/b7
 02000065->02006906 Xeon D-21xx CLX-SP B0 6-55-6/bf
 0400002c->04002f01 Xeon Scalable Gen2 CLX-SP B1 6-55-7/bf
 0500002c->04002f01 Xeon Scalable Gen2 SKL-H/S R0/N0 6-5e-3/36
 000000d6->000000dc Core Gen6, Xeon E3 v5 AML-Y22 H0
 6-8e-9/10 000000ca->000000d6 Core Gen8 Mobile KBL-U/Y H0
 6-8e-9/c0 000000ca->000000d6 Core Gen7 Mobile CFL-U43e D0
 6-8e-a/c0 000000ca->000000d6 Core Gen8 Mobile WHL-U W0
 6-8e-b/d0 000000ca->000000d6 Core Gen8 Mobile AML-Y42 V0
 6-8e-c/94 000000ca->000000d6 Core Gen10 Mobile CML-Y42 V0
 6-8e-c/94 000000ca->000000d6 Core Gen10 Mobile WHL-U V0
 6-8e-c/94 000000ca->000000d6 Core Gen8 Mobile KBL-G/H/S/E3 B0
 6-9e-9/2a 000000ca->000000d6 Core Gen7, Xeon E3 v6 CFL-H/S/E3
 U0 6-9e-a/22 000000ca->000000d6 Core Gen8 Desktop, Mobile, Xeon E
 CFL-S B0 6-9e-b/02 000000ca->000000d6 Core Gen8
 CFL-H/S P0 6-9e-c/22 000000ca->000000d6 Core Gen9
 CFL-H R0 6-9e-d/22 000000ca->000000d6 Core Gen9 Mobile

Also contains the Intel CPU Microcode update to 20200520:

 Processor Identifier Version Products Model Stepping F-MO-S/PI Old->New
 ---- new platforms ----------------------------------------
 ---- updated platforms ------------------------------------ SNB-E/EN/EP
 C1/M0 6-2d-6/6d 0000061f->00000621 Xeon E3/E5, Core X SNB-E/EN/EP
 C2/M1 6-2d-7/6d 00000718->0000071a Xeon E3/E5, Core X");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20200602~3.25.1", rls:"SLES15.0SP1"))) {
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
