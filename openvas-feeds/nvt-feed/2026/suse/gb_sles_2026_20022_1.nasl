# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20022.1");
  script_cve_id("CVE-2025-46817", "CVE-2025-46818", "CVE-2025-46819", "CVE-2025-49844");
  script_tag(name:"creation_date", value:"2026-01-16 04:26:57 +0000 (Fri, 16 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-07 15:40:02 +0000 (Tue, 07 Oct 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20022-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20022-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620022-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250995");
  script_xref(name:"URL", value:"https://github.com/valkey-io/valkey/releases/tag/8.0.5");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023778.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security update of valkey' package(s) announced via the SUSE-SU-2026:20022-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-49844: Fixed that a Lua script may lead to remote code execution (bsc#1250995)
 - CVE-2025-46817: Fixed that a Lua script may lead to integer overflow and potential RCE (bsc#1250995)
 - CVE-2025-46818: Fixed that a Lua script can be executed in the context of another user (bsc#1250995)
 - CVE-2025-46819: Fixed LUA out-of-bound read (bsc#1250995)

 - Bug fixes:

 * Fix accounting for dual channel RDB bytes in replication stats (#2614)
 * Fix EVAL to report unknown error when empty error table is provided (#2229)
 * Fix use-after-free when active expiration triggers hashtable to shrink (#2257)
 * Fix MEMORY USAGE to account for embedded keys (#2290)
 * Fix memory leak when shrinking a hashtable without entries (#2288)
 * Prevent potential assertion in active defrag handling large allocations (#2353)
 * Prevent bad memory access when NOTOUCH client gets unblocked (#2347)
 * Converge divergent shard-id persisted in nodes.conf to primary's shard id (#2174)
 * Fix client tracking memory overhead calculation (#2360)
 * Fix RDB load per slot memory pre-allocation when loading from RDB snapshot (#2466)
 * Don't use AVX2 instructions if the CPU doesn't support it (#2571)
 * Fix bug where active defrag may be unable to defrag sparsely filled pages (#2656)

Changes from 8.0.5:

 [link moved to references]");

  script_tag(name:"affected", value:"'Security update of valkey' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"valkey", rpm:"valkey~8.0.6~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-compat-redis", rpm:"valkey-compat-redis~8.0.6~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"valkey-devel", rpm:"valkey-devel~8.0.6~160000.1.1", rls:"SLES16.0.0"))) {
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
