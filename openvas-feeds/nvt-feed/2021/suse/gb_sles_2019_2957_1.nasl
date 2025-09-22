# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2957.1");
  script_cve_id("CVE-2019-11135", "CVE-2019-11139");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-20 18:02:32 +0000 (Wed, 20 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2957-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2957-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192957-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2019:2957-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:
Updated to 20191112 security release (bsc#1155988)
 - Processor Identifier Version Products
 - Model Stepping F-MO-S/PI Old->New
 - ---- new platforms ----------------------------------------
 - CML-U62 A0 6-a6-0/80 000000c6 Core Gen10 Mobile
 - CNL-U D0 6-66-3/80 0000002a Core Gen8 Mobile
 - SKX-SP B1 6-55-3/97 01000150 Xeon Scalable
 - ICL U/Y D1 6-7e-5/80 00000046 Core Gen10 Mobile
 - ---- updated platforms ------------------------------------
 - SKL U/Y D0 6-4e-3/c0 000000cc->000000d4 Core Gen6 Mobile
 - SKL H/S/E3 R0/N0 6-5e-3/36 000000cc->000000d4 Core Gen6
 - AML-Y22 H0 6-8e-9/10 000000b4->000000c6 Core Gen8 Mobile
 - KBL-U/Y H0 6-8e-9/c0 000000b4->000000c6 Core Gen7 Mobile
 - CFL-U43e D0 6-8e-a/c0 000000b4->000000c6 Core Gen8 Mobile
 - WHL-U W0 6-8e-b/d0 000000b8->000000c6 Core Gen8 Mobile
 - AML-Y V0 6-8e-c/94 000000b8->000000c6 Core Gen10 Mobile
 - CML-U42 V0 6-8e-c/94 000000b8->000000c6 Core Gen10 Mobile
 - WHL-U V0 6-8e-c/94 000000b8->000000c6 Core Gen8 Mobile
 - KBL-G/X H0 6-9e-9/2a 000000b4->000000c6 Core Gen7/Gen8
 - KBL-H/S/E3 B0 6-9e-9/2a 000000b4->000000c6 Core Gen7, Xeon E3
 v6
 - CFL-H/S/E3 U0 6-9e-a/22 000000b4->000000c6 Core Gen8 Desktop,
 Mobile, Xeon E
 - CFL-S B0 6-9e-b/02 000000b4->000000c6 Core Gen8
 - CFL-H R0 6-9e-d/22 000000b8->000000c6 Core Gen9 Mobile

Includes security fixes for:
 - CVE-2019-11135: Added feature allowing to disable TSX RTM (bsc#1139073)
 - CVE-2019-11139: A CPU microcode only fix for Voltage modulation issues
 (bsc#1141035)");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20191112~3.28.1", rls:"SLES15.0"))) {
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
