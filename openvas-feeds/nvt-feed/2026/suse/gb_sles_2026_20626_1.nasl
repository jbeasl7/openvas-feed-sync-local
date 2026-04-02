# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20626.1");
  script_cve_id("CVE-2025-22869", "CVE-2025-31133", "CVE-2025-47913", "CVE-2025-47914", "CVE-2025-52565", "CVE-2025-52881", "CVE-2025-6032", "CVE-2025-9566");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-24 14:15:30 +0000 (Tue, 24 Jun 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20626-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20626-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620626-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253993");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024648.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman' package(s) announced via the SUSE-SU-2026:20626-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podman fixes the following issues:

Changes in podman:

- Add symlink to catatonit in /usr/libexec/podman (bsc#1248988)

- CVE-2025-47914: Fixed golang.org/x/crypto/ssh/agent: non validated message size can cause a panic due to an out of bounds read (bsc#1253993)
- CVE-2025-47913: Fixed golang.org/x/crypto/ssh/agent: client process termination when receiving an unexpected message type in response to a key listing or signing request (bsc#1253542):

- CVE-2025-31133,CVE-2025-52565,CVE-2025-52881: Fixed runc: Container breakouts by bypassing runc's restrictions for writing to arbitrary /proc files (bsc#1252376):
- CVE-2025-9566: Fixed that podman kube play command may overwrite host files (bsc#1249154):");

  script_tag(name:"affected", value:"'podman' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~5.4.2~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~5.4.2~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~5.4.2~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podmansh", rpm:"podmansh~5.4.2~160000.4.1", rls:"SLES16.0.0"))) {
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
