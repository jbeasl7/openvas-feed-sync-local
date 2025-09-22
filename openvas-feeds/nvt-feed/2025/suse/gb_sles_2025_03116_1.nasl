# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03116.1");
  script_cve_id("CVE-2025-20053", "CVE-2025-20109", "CVE-2025-22839", "CVE-2025-22840", "CVE-2025-22889", "CVE-2025-26403", "CVE-2025-32086");
  script_tag(name:"creation_date", value:"2025-09-11 04:08:50 +0000 (Thu, 11 Sep 2025)");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03116-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03116-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503116-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248438");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041549.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl' package(s) announced via the SUSE-SU-2025:03116-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for microcode_ctl fixes the following issues:

- Intel CPU Microcode was updated to the 20250812 release (bsc#1248438)
 - CVE-2025-20109: Improper Isolation or Compartmentalization in the stream cache mechanism for some Intel Processors may allow an authenticated user to potentially enable escalation of privilege via local access.
 - CVE-2025-22840: Sequence of processor instructions leads to unexpected behavior for some Intel Xeon 6 Scalable processors may allow an authenticated user to potentially enable escalation of privilege via local access
 - CVE-2025-22839: Insufficient granularity of access control in the OOB-MSM for some Intel Xeon 6 Scalable processors may allow a privileged user to potentially enable escalation of privilege via adjacent access.
 - CVE-2025-22889: Improper handling of overlap between protected memory ranges for some Intel Xeon 6 processor with Intel TDX may allow a privileged user to potentially enable escalation of privilege via local access.
 - CVE-2025-20053: Improper buffer restrictions for some Intel Xeon Processor firmware with SGX enabled may allow a privileged user to potentially enable escalation of privilege via local access.
 - CVE-2025-26403: Out-of-bounds write in the memory subsystem for some Intel Xeon 6 processors when using Intel SGX or Intel TDX may allow a privileged user to potentially enable escalation of privilege via local access.
 - CVE-2025-32086: Improperly implemented security check for standard in the DDRIO configuration for some Intel Xeon 6 Processors when using Intel SGX or Intel TDX may allow a privileged user to potentially enable escalation of privilege via local access.
 - Update for functional issues.
 - Updated Platforms:

 <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> ARL-H <pipe> A1 <pipe> 06-c5-02/82 <pipe> 00000118 <pipe> 00000119 <pipe> Core Ultra Processor (Series 2)
 <pipe> ARL-S/HX (8P) <pipe> B0 <pipe> 06-c6-02/82 <pipe> 00000118 <pipe> 00000119 <pipe> Core Ultra Processor (Series 2)
 <pipe> EMR-SP <pipe> A1 <pipe> 06-cf-02/87 <pipe> 210002a9 <pipe> 210002b3 <pipe> Xeon Scalable Gen5
 <pipe> GNR-AP/SP <pipe> B0 <pipe> 06-ad-01/95 <pipe> 010003a2 <pipe> 010003d0 <pipe> Xeon Scalable Gen6
 <pipe> GNR-AP/SP <pipe> H0 <pipe> 06-ad-01/20 <pipe> 0a0000d1 <pipe> 0a000100 <pipe> Xeon Scalable Gen6
 <pipe> ICL-D <pipe> B0 <pipe> 06-6c-01/10 <pipe> 010002d0 <pipe> 010002e0 <pipe> Xeon D-17xx, D-27xx
 <pipe> ICX-SP <pipe> Dx/M1 <pipe> 06-6a-06/87 <pipe> 0d000404 <pipe> 0d000410 <pipe> Xeon Scalable Gen3
 <pipe> LNL <pipe> B0 <pipe> 06-bd-01/80 <pipe> 0000011f <pipe> 00000123 <pipe> Core Ultra 200 V Series Processor
 <pipe> MTL <pipe> C0 <pipe> 06-aa-04/e6 <pipe> 00000024 <pipe> 00000025 <pipe> Core(tm) Ultra Processor
 <pipe> RPL-H/P/PX ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'microcode_ctl' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~1.17~102.83.87.1", rls:"SLES11.0SP4"))) {
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
