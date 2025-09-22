# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3271.1");
  script_cve_id("CVE-2020-8695", "CVE-2020-8698");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:50 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-24 15:31:57 +0000 (Tue, 24 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3271-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3271-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203271-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2020:3271-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

Intel CPU Microcode updated to 20201027 pre-release

CVE-2020-8695: Fixed Intel RAPL sidechannel attack (SGX) (bsc#1170446)

CVE-2020-8698: Fixed Fast Store Forward Predictor INTEL-SA-00381
 (bsc#1173594)

 # New Platforms: <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe>
New Ver <pipe> Products
<pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> TGL <pipe> B1 <pipe> 06-8c-01/80 <pipe> <pipe> 00000068 <pipe> Core Gen11 Mobile <pipe> CPX-SP <pipe> A1 <pipe> 06-55-0b/bf <pipe> <pipe>
0700001e <pipe> Xeon Scalable Gen3 <pipe> CML-H <pipe> R1 <pipe> 06-a5-02/20
<pipe> <pipe> 000000e0 <pipe> Core Gen10 Mobile <pipe> CML-S62 <pipe> G1 <pipe>
06-a5-03/22 <pipe> <pipe> 000000e0 <pipe> Core Gen10 <pipe> CML-S102 <pipe> Q0
<pipe> 06-a5-05/22 <pipe> <pipe> 000000e0 <pipe> Core Gen10 <pipe> CML-U62 V2 <pipe>
K0 <pipe> 06-a6-01/80 <pipe> <pipe> 000000e0 <pipe> Core Gen10 Mobile # Updated Platforms: <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver
<pipe> Products
<pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> GKL-R <pipe> R0 <pipe> 06-7a-08/01 <pipe> 00000016 <pipe> 00000018 <pipe> Pentium J5040/N5030, Celeron J4125/J4025/N4020/N4120 <pipe> SKL-U/Y <pipe> D0 <pipe>
06-4e-03/c0 <pipe> 000000d6 <pipe> 000000e2 <pipe> Core Gen6 Mobile <pipe> SKL-U23e <pipe>
K1 <pipe> 06-4e-03/c0 <pipe> 000000d6 <pipe> 000000e2 <pipe> Core Gen6 Mobile <pipe>
APL <pipe> D0 <pipe> 06-5c-09/03 <pipe> 00000038 <pipe> 00000040 <pipe> Pentium N/J4xxx, Celeron N/J3xxx, Atom x5/7-E39xx <pipe> APL <pipe> E0 <pipe>
06-5c-0a/03 <pipe> 00000016 <pipe> 0000001e <pipe> Atom x5-E39xx <pipe> SKL-H/S <pipe>
R0/N0 <pipe> 06-5e-03/36 <pipe> 000000d6 <pipe> 000000e2 <pipe> Core Gen6, Xeon E3 v5 <pipe>
HSX-E/EP <pipe> Cx/M1 <pipe> 06-3f-02/6f <pipe> 00000043 <pipe> 00000044 <pipe> Core Gen4 X series, Xeon E5 v3 <pipe> SKX-SP <pipe> B1 <pipe> 06-55-03/97 <pipe> 01000157
<pipe> 01000159 <pipe> Xeon Scalable <pipe> SKX-SP <pipe> H0/M0/U0 <pipe> 06-55-04/b7 <pipe>
02006906 <pipe> 02006a08 <pipe> Xeon Scalable <pipe> SKX-D <pipe> M1 <pipe>
06-55-04/b7 <pipe> 02006906 <pipe> 02006a08 <pipe> Xeon D-21xx <pipe> CLX-SP <pipe>
B0 <pipe> 06-55-06/bf <pipe> 04002f01 <pipe> 04003003 <pipe> Xeon Scalable Gen2 <pipe>
CLX-SP <pipe> B1 <pipe> 06-55-07/bf <pipe> 05002f01 <pipe> 05003003 <pipe> Xeon Scalable Gen2 <pipe> ICL-U/Y <pipe> D1 <pipe> 06-7e-05/80 <pipe> 00000078 <pipe>
000000a0 <pipe> Core Gen10 Mobile <pipe> AML-Y22 <pipe> H0 <pipe> 06-8e-09/10 <pipe>
000000d6 <pipe> 000000de <pipe> Core Gen8 Mobile <pipe> KBL-U/Y <pipe> H0 <pipe>
06-8e-09/c0 <pipe> 000000d6 <pipe> 000000de <pipe> Core Gen7 Mobile <pipe> CFL-U43e <pipe>
D0 <pipe> 06-8e-0a/c0 <pipe> 000000d6 <pipe> 000000e0 <pipe> Core Gen8 Mobile ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20201027~2.7.1", rls:"SLES15.0SP2"))) {
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
