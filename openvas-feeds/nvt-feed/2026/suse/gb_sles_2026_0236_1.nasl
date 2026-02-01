# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0236.1");
  script_cve_id("CVE-2025-46394", "CVE-2025-60876");
  script_tag(name:"creation_date", value:"2026-01-26 08:39:16 +0000 (Mon, 26 Jan 2026)");
  script_version("2026-01-27T05:49:07+0000");
  script_tag(name:"last_modification", value:"2026-01-27 05:49:07 +0000 (Tue, 27 Jan 2026)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-24 14:38:22 +0000 (Wed, 24 Sep 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0236-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260236-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253245");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023849.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the SUSE-SU-2026:0236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for busybox fixes the following issues:

This update for busybox fixes the following issues:

Security issues:

- CVE-2025-46394: Fixed tar hidden files via escape sequence (CVE-2025-46394, bsc#1241661)
- CVE-2025-60876: Fixed HTTP request header injection in wget (CVE-2025-60876, bsc#1253245)

Other issues:

- Set CONFIG_FIRST_SYSTEM_ID to 201 to avoid confclict (bsc#1236670)
- Fixed unshare -mrpf sh core dump on ppc64le (bsc#1249237)
- Fixed adduser inside containers on an SELinux host (bsc#1247779)");

  script_tag(name:"affected", value:"'busybox' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.37.0~150500.10.14.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.37.0~150500.10.14.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.37.0~150500.10.14.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.37.0~150500.10.14.1", rls:"SLES15.0SP6"))) {
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
