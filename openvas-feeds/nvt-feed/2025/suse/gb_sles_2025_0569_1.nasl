# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0569.1");
  script_cve_id("CVE-2024-31068", "CVE-2024-36293", "CVE-2024-37020", "CVE-2024-39355");
  script_tag(name:"creation_date", value:"2025-02-19 11:58:11 +0000 (Wed, 19 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0569-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0569-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250569-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237096");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020362.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2025:0569-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

- Intel CPU Microcode was updated to the 20250211 release (bsc#1237096)

 - CVE-2024-31068: Improper Finite State Machines (FSMs) in Hardware Logic for some Intel Processors may allow privileged user to potentially enable denial of service via local access.
 - CVE-2024-36293: A potential security vulnerability in some Intel Software Guard Extensions (Intel SGX) Platforms may allow denial of service. Intel is releasing microcode updates to mitigate this potential vulnerability.
 - CVE-2024-39355: A potential security vulnerability in some 13th and 14th Generation Intel Core Processors may allow denial of service. Intel is releasing microcode and UEFI reference code updates to mitigate this potential vulnerability.
 - CVE-2024-37020: A potential security vulnerability in the Intel Data Streaming Accelerator (Intel DSA) for some Intel Xeon Processors may allow denial of service. Intel is releasing software updates to mitigate this potential vulnerability.

 New Platforms
 <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> SRF-SP <pipe> C0 <pipe> 06-af-03/01 <pipe> <pipe> 03000330 <pipe> Xeon 6700-Series Processors with E-Cores
 ### Updated Platforms
 <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> ADL <pipe> C0 <pipe> 06-97-02/07 <pipe> 00000037 <pipe> 00000038 <pipe> Core Gen12
 <pipe> ADL <pipe> H0 <pipe> 06-97-05/07 <pipe> 00000037 <pipe> 00000038 <pipe> Core Gen12
 <pipe> ADL <pipe> L0 <pipe> 06-9a-03/80 <pipe> 00000435 <pipe> 00000436 <pipe> Core Gen12
 <pipe> ADL <pipe> R0 <pipe> 06-9a-04/80 <pipe> 00000435 <pipe> 00000436 <pipe> Core Gen12
 <pipe> ADL-N <pipe> N0 <pipe> 06-be-00/19 <pipe> 0000001a <pipe> 0000001c <pipe> Core i3-N305/N300, N50/N97/N100/N200, Atom x7211E/x7213E/x7425E
 <pipe> AZB <pipe> A0/R0 <pipe> 06-9a-04/40 <pipe> 00000007 <pipe> 00000009 <pipe> Intel(R) Atom(R) C1100
 <pipe> CFL-H <pipe> R0 <pipe> 06-9e-0d/22 <pipe> 00000100 <pipe> 00000102 <pipe> Core Gen9 Mobile
 <pipe> CFL-H/S/E3 <pipe> U0 <pipe> 06-9e-0a/22 <pipe> 000000f8 <pipe> 000000fa <pipe> Core Gen8 Desktop, Mobile, Xeon E
 <pipe> EMR-SP <pipe> A0 <pipe> 06-cf-01/87 <pipe> 21000283 <pipe> 21000291 <pipe> Xeon Scalable Gen5
 <pipe> EMR-SP <pipe> A1 <pipe> 06-cf-02/87 <pipe> 21000283 <pipe> 21000291 <pipe> Xeon Scalable Gen5
 <pipe> ICL-D <pipe> B0 <pipe> 06-6c-01/10 <pipe> 010002b0 <pipe> 010002c0 <pipe> Xeon D-17xx, D-27xx
 <pipe> ICX-SP <pipe> Dx/M1 <pipe> 06-6a-06/87 <pipe> 0d0003e7 <pipe> 0d0003f5 <pipe> Xeon Scalable Gen3
 <pipe> RPL-E/HX/S <pipe> B0 <pipe> 06-b7-01/32 <pipe> 0000012b <pipe> 0000012c <pipe> Core ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20250211~149.2", rls:"SLES12.0SP5"))) {
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
