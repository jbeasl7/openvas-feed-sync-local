# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0659.1");
  script_cve_id("CVE-2025-30204");
  script_tag(name:"creation_date", value:"2026-03-02 04:37:24 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0659-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0659-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260659-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240513");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024451.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-stable' package(s) announced via the SUSE-SU-2026:0659-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker-stable fixes the following issues:

- CVE-2025-30204: Fixed a vulnerability in jwt-go which allowed excessive memory allocation during header parsing. (bsc#1240513)");

  script_tag(name:"affected", value:"'docker-stable' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-stable", rpm:"docker-stable~24.0.9_ce~150000.1.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-bash-completion", rpm:"docker-stable-bash-completion~24.0.9_ce~150000.1.36.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"docker-stable", rpm:"docker-stable~24.0.9_ce~150000.1.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-bash-completion", rpm:"docker-stable-bash-completion~24.0.9_ce~150000.1.36.1", rls:"SLES15.0SP5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"docker-stable", rpm:"docker-stable~24.0.9_ce~150000.1.36.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-bash-completion", rpm:"docker-stable-bash-completion~24.0.9_ce~150000.1.36.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-zsh-completion", rpm:"docker-stable-zsh-completion~24.0.9_ce~150000.1.36.1", rls:"SLES15.0SP6"))) {
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
