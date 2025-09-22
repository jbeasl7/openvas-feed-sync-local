# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0684.1");
  script_cve_id("CVE-2019-17361", "CVE-2019-18897");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-04 14:58:59 +0000 (Wed, 04 Mar 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0684-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0684-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200684-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the SUSE-SU-2020:0684-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:
Avoid possible user escalation upgrading salt-master (bsc#1157465)
 (CVE-2019-18897)

Fix unit tests failures in test_batch_async tests

Batch Async: Handle exceptions, properly unregister and close instances
 after running async batching to avoid CPU starvation of the MWorkers
 (bsc#1162327)

RHEL/CentOS 8 uses platform-python instead of python3

New configuration option for selection of grains in the minion start
 event.

Fix 'os_family' grain for Astra Linux Common Edition

Fix for salt-api NET API where unauthenticated attacker could run
 arbitrary code (CVE-2019-17361) (bsc#1162504)

Adds disabled parameter to mod_repo in aptpkg module Move token with
 atomic operation Bad API token files get deleted (bsc#1160931)

Support for Btrfs and XFS in parted and mkfs added

Adds list_downloaded for apt Module to enable pre-downloading support
 Adds virt.(pool<pipe>network)_get_xml functions

Various libvirt updates:
 * Add virt.pool_capabilities function
 * virt.pool_running improvements
 * Add virt.pool_deleted state
 * virt.network_define allow adding IP configuration

virt: adding kernel boot parameters to libvirt xml

Fix to scheduler when data['run'] does not exist (bsc#1159118)

Fix virt states to not fail on VMs already stopped

Fix applying of attributes for returner rawfile_json (bsc#1158940)

xfs: do not fail if type is not present (bsc#1153611)

Fix errors when running virt.get_hypervisor function

Align virt.full_info fixes with upstream Salt

Fix for log checking in x509 test

Read repo info without using interpolation (bsc#1135656)

Limiting M2Crypto to >= SLE15

Replacing pycrypto with M2Crypto (bsc#1165425)");

  script_tag(name:"affected", value:"'salt' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Python2 15-SP1, SUSE Linux Enterprise Module for Server Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-salt", rpm:"python2-salt~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~2019.2.0~6.24.1", rls:"SLES15.0SP1"))) {
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
