# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20202.1");
  script_cve_id("CVE-2025-39963", "CVE-2025-40204", "CVE-2025-40212");
  script_tag(name:"creation_date", value:"2026-02-05 04:36:37 +0000 (Thu, 05 Feb 2026)");
  script_version("2026-02-05T05:56:23+0000");
  script_tag(name:"last_modification", value:"2026-02-05 05:56:23 +0000 (Thu, 05 Feb 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-03 14:21:09 +0000 (Tue, 03 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20202-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20202-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620202-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254196");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 1 for SUSE Linux Enterprise 16)' package(s) announced via the SUSE-SU-2026:20202-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the SUSE Linux Enterprise kernel 6.12.0-160000.6.1 fixes various security issues

The following security issues were fixed:

- CVE-2025-39963: io_uring: fix incorrect io_kiocb reference in io_link_skb (bsc#1251982).
- CVE-2025-40204: sctp: Fix MAC comparison to be constant-time (bsc#1253437).
- CVE-2025-40212: nfsd: fix refcount leak in nfsd_set_fh_dentry() (bsc#1254196).

The following non security issues was fixed:

- Explicitly add module-common.c with vermagic and retpoline modinfo (bsc#1252270).");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-6_12_0-160000_6-default", rpm:"kernel-livepatch-6_12_0-160000_6-default~3~160000.1.1", rls:"SLES16.0.0"))) {
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
