# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0923.1");
  script_cve_id("CVE-2026-28295", "CVE-2026-28296");
  script_tag(name:"creation_date", value:"2026-03-20 04:36:23 +0000 (Fri, 20 Mar 2026)");
  script_version("2026-03-20T05:55:14+0000");
  script_tag(name:"last_modification", value:"2026-03-20 05:55:14 +0000 (Fri, 20 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-26 16:24:09 +0000 (Thu, 26 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0923-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260923-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258954");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024712.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gvfs' package(s) announced via the SUSE-SU-2026:0923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gvfs fixes the following issues:

- CVE-2026-28295: Fix ftp use control connection address for PASV data (bsc#1258953).
- CVE-2026-28296: Fix ftp reject paths containing CR/LF characters (bsc#1258954).");

  script_tag(name:"affected", value:"'gvfs' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"gvfs", rpm:"gvfs~1.48.2~150400.4.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-afc", rpm:"gvfs-backend-afc~1.48.2~150400.4.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-samba", rpm:"gvfs-backend-samba~1.48.2~150400.4.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backends", rpm:"gvfs-backends~1.48.2~150400.4.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-devel", rpm:"gvfs-devel~1.48.2~150400.4.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-fuse", rpm:"gvfs-fuse~1.48.2~150400.4.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-lang", rpm:"gvfs-lang~1.48.2~150400.4.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gvfs", rpm:"gvfs~1.48.2~150400.4.9.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-afc", rpm:"gvfs-backend-afc~1.48.2~150400.4.9.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backend-samba", rpm:"gvfs-backend-samba~1.48.2~150400.4.9.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-backends", rpm:"gvfs-backends~1.48.2~150400.4.9.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-devel", rpm:"gvfs-devel~1.48.2~150400.4.9.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-fuse", rpm:"gvfs-fuse~1.48.2~150400.4.9.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvfs-lang", rpm:"gvfs-lang~1.48.2~150400.4.9.1", rls:"SLES15.0SP5"))) {
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
