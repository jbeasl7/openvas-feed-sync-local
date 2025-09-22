# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01650.1");
  script_cve_id("CVE-2024-28956", "CVE-2024-43420", "CVE-2024-45332", "CVE-2025-20012", "CVE-2025-20054", "CVE-2025-20103", "CVE-2025-20623", "CVE-2025-24495");
  script_tag(name:"creation_date", value:"2025-05-26 04:11:26 +0000 (Mon, 26 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01650-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01650-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501650-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243123");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039307.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2025:01650-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

Intel CPU Microcode was updated to the 20250512 release (bsc#1243123)

- CVE-2024-28956: Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution for some Intel Processors may allow an authenticated user to potentially enable information disclosure via local access.
- CVE-2025-20103: Insufficient resource pool in the core management mechanism for some Intel Processors may allow an authenticated user to potentially enable denial of service via local access.
- CVE-2025-20054: Uncaught exception in the core management mechanism for some Intel Processors may allow an authenticated user to potentially enable denial of service via local access.
- CVE-2024-43420: Exposure of sensitive information caused by shared microarchitectural predictor state that influences transient execution for some Intel Atom processors may allow an authenticated user to potentially enable information disclosure via local access.
- CVE-2025-20623: Exposure of sensitive information caused by shared microarchitectural predictor state that influences transient execution for some Intel Core processors (10th Generation) may allow an authenticated user to potentially enable information disclosure via local access.
- CVE-2024-45332: Exposure of sensitive information caused by shared microarchitectural predictor state that influences transient execution in the indirect branch predictors for some Intel Processors may allow an authenticated user to potentially enable information disclosure via local access.
- CVE-2025-24495: Incorrect initialization of resource in the branch prediction unit for some Intel Core Ultra Processors may allow an authenticated user to potentially enable information disclosure via local access.
- CVE-2025-20012: Incorrect behavior order for some Intel Core Ultra Processors may allow an unauthenticated user to potentially enable information disclosure via physical access.
- Updates for functional issues.

- New Platforms

 <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> ARL-U <pipe> A1 <pipe> 06-b5-00/80 <pipe> <pipe> 0000000a <pipe> Core Ultra Processor (Series2)
 <pipe> ARL-S/HX (8P) <pipe> B0 <pipe> 06-c6-02/82 <pipe> <pipe> 00000118 <pipe> Core Ultra Processor (Series2)
 <pipe> ARL-H <pipe> A1 <pipe> 06-c5-02/82 <pipe> <pipe> 00000118 <pipe> Core Ultra Processor (Series2)
 <pipe> GNR-AP/SP <pipe> B0 <pipe> 06-ad-01/95 <pipe> <pipe> 010003a2 <pipe> Xeon Scalable Gen6
 <pipe> GNR-AP/SP <pipe> H0 <pipe> 06-ad-01/20 <pipe> <pipe> 0a0000d1 <pipe> Xeon Scalable Gen6
 <pipe> LNL <pipe> B0 <pipe> 06-bd-01/80 <pipe> <pipe> 0000011f <pipe> Core Ultra 200 V Series Processor

- Updated Platforms

 <pipe> Processor <pipe> Stepping <pipe> ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20250512~152.1", rls:"SLES12.0SP5"))) {
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
