# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1973.1");
  script_cve_id("CVE-2019-18897", "CVE-2020-11651", "CVE-2020-11652");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-06 16:46:34 +0000 (Wed, 06 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1973-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1973-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201973-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174165");
  script_xref(name:"URL", value:"https://docs.saltstack.com/en/latest/topics/releases/3000.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-July/007163.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Salt' package(s) announced via the SUSE-SU-2020:1973-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

salt:

- Fix for TypeError in Tornado importer (bsc#1174165)
- Require python3-distro only for TW (bsc#1173072)
- Various virt backports from 3000.2
- Avoid traceback on debug logging for swarm module (bsc#1172075)
- Add publish_batch to ClearFuncs exposed methods
- Update to salt version 3000
 See release notes: [link moved to references]
- Zypperpkg: filter patterns that start with dot (bsc#1171906)
- Batch mode now also correctly provides return value (bsc#1168340)
- Add docker.logout to docker execution module (bsc#1165572)
- Testsuite fix
- Add option to enable/disable force refresh for zypper
- Python3.8 compatibility changes
- Prevent sporious 'salt-api' stuck processes when managing SSH minions because of logging deadlock (bsc#1159284)
- Avoid segfault from 'salt-api' under certain conditions of heavy load managing SSH minions (bsc#1169604)
- Revert broken changes to slspath made on Salt 3000 (saltstack/salt#56341) (bsc#1170104)
- Returns a the list of IPs filtered by the optional network list
- Fix CVE-2020-11651 and CVE-2020-11652 (bsc#1170595)
- Do not require vendored backports-abc (bsc#1170288)
- Fix partition.mkpart to work without fstype (bsc#1169800)
- Enable building and installation for Fedora
- Disable python2 build on Tumbleweed
 We are removing the python2 interpreter from openSUSE (SLE16).
 As such disable salt building for python2 there.
- More robust remote port detection
- Sanitize grains loaded from roster_grains.json cache during 'state.pkg'
- Do not make file.recurse state to fail when msgpack 0.5.4 (bsc#1167437)
- Build: Buildequire pkgconfig(systemd) instead of systemd
 pkgconfig(systemd) is provided by systemd, so this is de-facto no change.
 But inside the Open Build Service (OBS), the same symbol is also provided by
 systemd-mini, which exists to shorten build-chains by only enabling what other
 packages need to successfully build
- Add new custom SUSE capability for saltutil state module
- Fixes status attribute issue in aptpkg test
- Make setup.py script not to require setuptools greater than 9.1
- Loop: fix variable names for until_no_eval
- Drop conflictive module.run state patch (bsc#1167437)
- Update patches after rebase with upstream v3000 tag (bsc#1167437)
- Fix some requirements issues depending on Python3 versions
- Removes obsolete patch
- Fix for low rpm_lowpkg unit test
- Add python-singledispatch as dependency for python2-salt
- Virt._get_domain: don't raise an exception if there is no VM
- Fix for temp folder definition in loader unit test
- Adds test for zypper abbreviation fix
- Improved storage pool or network handling
- Better import cache handline
- Make 'salt.ext.tornado.gen' to use 'salt.ext.backports_abc' on Python 2
- Fix regression in service states with reload argument
- Fix integration test failure for test_mod_del_repo_multiline_values
- Fix for unless requisite when pip ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Salt' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"python2-salt", rpm:"python2-salt~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3000~5.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3000~5.78.1", rls:"SLES15.0"))) {
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
