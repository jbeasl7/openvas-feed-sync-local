# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2941.1");
  script_cve_id("CVE-2023-42667", "CVE-2023-49141", "CVE-2024-24853", "CVE-2024-24980", "CVE-2024-25939");
  script_tag(name:"creation_date", value:"2024-08-19 04:26:30 +0000 (Mon, 19 Aug 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2941-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2941-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242941-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229129");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/334663");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/337346");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/338025");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/338848");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/341079");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/615213");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/631123");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/634897");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/636674");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/637780");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/682436");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/709192");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/714071");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/740518");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/764616");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/792254");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036482.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01038.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01046.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01083.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01100.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01118.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2024:2941-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

- Intel CPU Microcode was updated to the 20240813 release (bsc#1229129)
 - CVE-2024-24853: Security updates for [INTEL-SA-01083]([link moved to references])
 - CVE-2024-25939: Security updates for [INTEL-SA-01118]([link moved to references])
 - CVE-2024-24980: Security updates for [INTEL-SA-01100]([link moved to references])
 - CVE-2023-42667: Security updates for [INTEL-SA-01038]([link moved to references])
 - CVE-2023-49141: Security updates for [INTEL-SA-01046]([link moved to references])
 Other issues fixed:
 - Update for functional issues. Refer to [Intel Core Ultra Processor]([link moved to references]) for details.
 - Update for functional issues. Refer to [3rd Generation Intel Xeon Processor Scalable Family Specification Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [3rd Generation Intel Xeon Scalable Processors Specification Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [2nd Generation Intel Xeon Processor Scalable Family Specification Update]([link moved to references]) for details
 - Update for functional issues. Refer to [Intel Xeon D-2700 Processor Specification Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [Intel Xeon E-2300 Processor Specification Update ]([link moved to references]) for details.
 - Update for functional issues. Refer to [13th Generation Intel Core Processor Specification Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [12th Generation Intel Core Processor Family]([link moved to references]) for details.
 - Update for functional issues. Refer to [11th Gen Intel Core Processor Specification Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [10th Gen Intel Core Processor Families Specification Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [10th Generation Intel Core Processor Specification Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [8th and 9th Generation Intel Core Processor Family Spec Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [8th Generation Intel Core Processor Families Specification Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [7th and 8th Generation Intel Core Processor Specification Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [Intel Processors and Intel Core i3 N-Series]([link moved to references]) for details.
 - Update for functional issues. Refer to [Intel Atom x6000E Series, and Intel Pentium and Celeron N and J Series Processors for Internet of Things (IoT) Applications]([link moved to references]) for details.
 Updated ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20240813~140.1", rls:"SLES12.0SP5"))) {
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
