# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0605.1");
  script_cve_id("CVE-2023-33850", "CVE-2024-20918", "CVE-2024-20919", "CVE-2024-20921", "CVE-2024-20926", "CVE-2024-20932", "CVE-2024-20945", "CVE-2024-20952");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 22:15:40 +0000 (Tue, 16 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0605-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0605-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240605-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219843");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/018004.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2024:0605-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2023-33850: Fixed information disclosure vulnerability due to the consumed GSKit library (bsc#1219843).
- CVE-2024-20932: Fixed incorrect handling of ZIP files with duplicate entries (bsc#1218908).
- CVE-2024-20952: Fixed RSA padding issue and timing side-channel attack against TLS (bsc#1218911).
- CVE-2024-20918: Fixed array out-of-bounds access due to missing range check in C1 compiler (bsc#1218907).
- CVE-2024-20921: Fixed range check loop optimization issue (bsc#1218905).
- CVE-2024-20919: Fixed JVM class file verifier flaw allows unverified bytecode execution (bsc#1218903).
- CVE-2024-20926: Fixed arbitrary Java code execution in Nashorn (bsc#1218906).
- CVE-2024-20945: Fixed logging of digital signature private keys (bsc#1218909).");

  script_tag(name:"affected", value:"'java-1_8_0-ibm' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm", rpm:"java-1_8_0-ibm~1.8.0_sr8.20~30.120.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-alsa", rpm:"java-1_8_0-ibm-alsa~1.8.0_sr8.20~30.120.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-devel", rpm:"java-1_8_0-ibm-devel~1.8.0_sr8.20~30.120.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-ibm-plugin", rpm:"java-1_8_0-ibm-plugin~1.8.0_sr8.20~30.120.1", rls:"SLES12.0SP5"))) {
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
