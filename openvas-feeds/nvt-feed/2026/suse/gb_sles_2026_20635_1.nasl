# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20635.1");
  script_cve_id("CVE-2025-38352", "CVE-2025-39698", "CVE-2025-39742", "CVE-2025-40129", "CVE-2025-40130", "CVE-2025-40186");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-09 19:09:30 +0000 (Fri, 09 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20635-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20635-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620635-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253473");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024643.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 0 for SUSE Linux Enterprise 16)' package(s) announced via the SUSE-SU-2026:20635-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the SUSE Linux Enterprise kernel 6.12.0-160000.5.1 fixes various security issues

The following security issues were fixed:

- CVE-2025-38352: posix-cpu-timers: fix race between handle_posix_cpu_timers() and posix_cpu_timer_del() (bsc#1249205).
- CVE-2025-39698: io_uring/futex: ensure io_futex_wait() cleans up properly on failure (bsc#1250190).
- CVE-2025-39742: RDMA: hfi1: fix possible divide-by-zero in find_hw_thread_mask() (bsc#1249480).
- CVE-2025-40129: sunrpc: fix null pointer dereference on zero-length checksum (bsc#1253473).
- CVE-2025-40130: scsi: ufs: core: Fix data race in CPU latency PM QoS request handling (bsc#1253415).
- CVE-2025-40186: tcp: Don't call reqsk_fastopen_remove() in tcp_conn_request() (bsc#1253439).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 0 for SUSE Linux Enterprise 16)' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-6_12_0-160000_5-default", rpm:"kernel-livepatch-6_12_0-160000_5-default~7~160000.4.3", rls:"SLES16.0.0"))) {
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
