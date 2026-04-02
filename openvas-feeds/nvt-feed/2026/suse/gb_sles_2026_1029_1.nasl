# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1029.1");
  script_cve_id("CVE-2025-13836", "CVE-2025-67724", "CVE-2025-67725", "CVE-2025-67726");
  script_tag(name:"creation_date", value:"2026-03-27 04:49:18 +0000 (Fri, 27 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-10 19:58:12 +0000 (Tue, 10 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1029-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1029-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261029-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254905");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024909.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the SUSE-SU-2026:1029-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:

- Security issues fixed:

 * CVE-2025-67724: Fixed missing validation of supplied reason phrase (bsc#1254903)
 * CVE-2025-67725: Fixed DoS via malicious HTTP request (bsc#1254905)
 * CVE-2025-67726: Fixed HTTP header parameter parsing algorithm (bsc#1254904)
 * CVE-2025-13836: Set a safe limit to http.client response read (bsc#1254400)

- Made syntax in httputil_test compatible with Python 3.6
- Fixed KeyError in postgres module with PostgreSQL 17 (bsc#1254325)
- Use internal deb classes instead of external aptsource lib
- Improved wheel key.finger call (bsc#1240532)
- Improved utils.find_json function (bsc#1246130)
- Extended warn_until period to 2027");

  script_tag(name:"affected", value:"'salt' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-salt", rpm:"python311-salt~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3006.0~150500.4.68.2", rls:"SLES15.0SP5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-salt", rpm:"python311-salt~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3006.0~150500.4.68.2", rls:"SLES15.0SP6"))) {
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
