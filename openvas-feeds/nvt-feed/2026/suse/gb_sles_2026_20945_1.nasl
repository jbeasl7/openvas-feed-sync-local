# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20945.1");
  script_cve_id("CVE-2025-40214", "CVE-2025-40258", "CVE-2025-40284", "CVE-2025-40297", "CVE-2025-68284", "CVE-2025-68285", "CVE-2025-68813", "CVE-2025-71085");
  script_tag(name:"creation_date", value:"2026-04-03 04:47:54 +0000 (Fri, 03 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-25 18:57:30 +0000 (Wed, 25 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20945-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20945-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620945-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257669");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045207.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 1 for SUSE Linux Enterprise 16)' package(s) announced via the SUSE-SU-2026:20945-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the SUSE Linux Enterprise Kernel 6.12.0-160000.6.1 fixes various security issues

The following security issues were fixed:

- CVE-2025-40214: af_unix: Initialise scc_index in unix_add_edge() (bsc#1255052).
- CVE-2025-40258: mptcp: fix race condition in mptcp_schedule_work() (bsc#1255053).
- CVE-2025-40284: Bluetooth: MGMT: cancel mesh send timer when hdev removed (bsc#1257669).
- CVE-2025-40297: net: bridge: fix use-after-free due to MST port state bypass (bsc#1255895).
- CVE-2025-68284: libceph: prevent potential out-of-bounds writes in handle_auth_session_key() (bsc#1255378).
- CVE-2025-68285: libceph: fix potential use-after-free in have_mon_and_osd_map() (bsc#1255402).
- CVE-2025-68813: ipvs: fix ipv4 null-ptr-deref in route error path (bsc#1256644).
- CVE-2025-71085: ipv6: BUG() in pskb_expand_head() as part of calipso_skbuff_setattr() (bsc#1256624).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 1 for SUSE Linux Enterprise 16)' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-6_12_0-160000_6-default", rpm:"kernel-livepatch-6_12_0-160000_6-default~6~160000.1.1", rls:"SLES16.0.0"))) {
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
