# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20941.1");
  script_cve_id("CVE-2024-24853", "CVE-2025-31648");
  script_tag(name:"creation_date", value:"2026-04-03 04:47:54 +0000 (Fri, 03 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20941-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20941-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620941-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258046");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045211.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2026:20941-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

- Intel CPU Microcode was updated to the 20260210 release (bsc#1258046):

 - CVE-2024-24853: Updated fix for incorrect behavior order in transition
 between executive monitor and SMI transfer monitor (STM) in some Intel(R)
 Processor may allow a privileged user to potentially enable escalation
 of privilege via local access (bsc#1229129).

 - CVE-2025-31648: Improper handling of values in the
 microcode flow for some Intel Processor Family may allow
 an escalation of privilege (bsc#1258046).

- Intel CPU Microcode was updated to the 20251111 release (bsc#1253319):

 - Update for functional issues.

- switch the supplements to use supplements + kernel to allow
 moving a installation to Intel hardware (bsc#1249138)

- Intel CPU Microcode was updated to the 20241029 release (bsc#1230400):

 - Update for functional issues.");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20260210~160000.1.1", rls:"SLES16.0.0"))) {
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
