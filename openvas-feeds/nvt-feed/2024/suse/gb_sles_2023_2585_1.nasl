# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2585.1");
  script_tag(name:"creation_date", value:"2024-02-28 04:22:22 +0000 (Wed, 28 Feb 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2585-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2585-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232585-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212517");
  script_xref(name:"URL", value:"https://docs.saltproject.io/en/latest/topics/releases/3006.0.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-February/034401.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt and python-pyzmq' package(s) announced via the SUSE-SU-2023:2585-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt and python-pyzmq fixes the following issues:

salt:

- Update to Salt release version 3006.0 (jsc#PED-4361)
 * See release notes: [link moved to references]
- Add missing patch after rebase to fix collections Mapping issues
- Add python3-looseversion as new dependency for salt
- Add python3-packaging as new dependency for salt
- Allow entrypoint compatibility for 'importlib-metadata>=5.0.0' (bsc#1207071)
- Avoid conflicts with Salt dependencies versions (bsc#1211612)
- Avoid failures due transactional_update module not available in Salt 3006.0 (bsc#1211754)
- Create new salt-tests subpackage containing Salt tests
- Drop conflictive patch dicarded from upstream
- Fix package build with old setuptools versions
- Fix SLS rendering error when Jinja macros are used
- Fix version detection and avoid building and testing failures
- Prevent deadlocks in salt-ssh executions
- Require python3-jmespath runtime dependency (bsc#1209233)
- Make master_tops compatible with Salt 3000 and older minions (bsc#1212516, bsc#1212517)

python-pyzmq:

- Update python-pyzmq to version 17.1.2 in LTSS products (bsc#1186945)");

  script_tag(name:"affected", value:"'salt and python-pyzmq' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"python2-pyzmq", rpm:"python2-pyzmq~17.1.2~150000.3.5.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyzmq", rpm:"python3-pyzmq~17.1.2~150000.3.5.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-transactional-update", rpm:"salt-transactional-update~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3006.0~150000.97.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"python2-pyzmq", rpm:"python2-pyzmq~17.1.2~150000.3.5.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyzmq", rpm:"python3-pyzmq~17.1.2~150000.3.5.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"python3-pyzmq", rpm:"python3-pyzmq~17.1.2~150000.3.5.2", rls:"SLES15.0SP3"))) {
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
