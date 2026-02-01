# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20123.1");
  script_cve_id("CVE-2025-31133", "CVE-2025-47913", "CVE-2025-47914", "CVE-2025-52565", "CVE-2025-52881");
  script_tag(name:"creation_date", value:"2026-01-30 04:34:32 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-03 18:30:15 +0000 (Wed, 03 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20123-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20123-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620123-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254054");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-January/043749.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah' package(s) announced via the SUSE-SU-2026:20123-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah fixes the following issues:

- CVE-2025-47914: golang.org/x/crypto/ssh/agent: Fixed non validated message size causing a panic due to an out
 of bounds read (bsc#1254054)
- CVE-2025-47913: golang.org/x/crypto/ssh/agent: Fixed client process termination when receiving an unexpected
 message type in response to a key listing or signing request (bsc#1253598)
- CVE-2025-31133,CVE-2025-52565,CVE-2025-52881: Fixed container breakouts by bypassing runc's restrictions for writing to arbitrary /proc
 files (bsc#1253096)

Other fixes:

- Updated to version 1.39.5.");

  script_tag(name:"affected", value:"'buildah' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.39.5~160000.1.1", rls:"SLES16.0.0"))) {
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
