# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1581.1");
  script_cve_id("CVE-2017-5200", "CVE-2017-8109");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-06 18:39:07 +0000 (Fri, 06 Oct 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1581-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1581-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171581-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043111");
  script_xref(name:"URL", value:"https://docs.saltstack.com/en/develop/topics/releases/2016.11.1.html");
  script_xref(name:"URL", value:"https://docs.saltstack.com/en/develop/topics/releases/2016.11.2.html");
  script_xref(name:"URL", value:"https://docs.saltstack.com/en/develop/topics/releases/2016.11.3.html");
  script_xref(name:"URL", value:"https://docs.saltstack.com/en/develop/topics/releases/2016.11.4.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-June/002947.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Salt' package(s) announced via the SUSE-SU-2017:1581-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt provides version 2016.11.4 and brings various fixes and improvements:

- Adding a salt-minion watchdog for RHEL6 and SLES11 systems (sysV) to restart salt-minion in case of crashes during upgrade.
- Fix format error. (bsc#1043111)
- Fix ownership for whole master cache directory. (bsc#1035914)
- Disable 3rd party runtime packages to be explicitly recommended. (bsc#1040886)
- Fix insecure permissions in salt-ssh temporary files. (bsc#1035912, CVE-2017-8109)
- Disable custom rosters for Salt SSH via Salt API. (bsc#1011800, CVE-2017-5200)
- Orchestrate and batches don't return false failed information anymore.
- Speed-up cherrypy by removing sleep call.
- Fix os_family grains on SUSE. (bsc#1038855)
- Fix setting the language on SUSE systems. (bsc#1038855)
- Use SUSE specific salt-api.service. (bsc#1039370)
- Fix using hostname for minion ID as '127'.
- Fix core grains constants for timezone. (bsc#1032931)
- Minor fixes on new pkg.list_downloaded.
- Listing all type of advisory patches for Yum module.
- Prevents zero length error on Python 2.6.
- Fixes zypper test error after backporting.
- Raet protocol is no longer supported. (bsc#1020831)
- Fix moving SSH data to the new home. (bsc#1027722)
- Fix logrotating /var/log/salt/minion. (bsc#1030009)
- Fix result of master_tops extension is mutually overwritten. (bsc#1030073)
- Allows to set 'timeout' and 'gather_job_timeout' via kwargs.
- Allows to set custom timeouts for 'manage.up' and 'manage.status'.
- Use salt's ordereddict for comparison.
- Fix scripts for salt-proxy.
- Add openscap module.
- File.get_managed regression fix.
- Fix translate variable arguments if they contain hidden keywords. (bsc#1025896)
- Added unit test for dockerng.sls_build dryrun.
- Added dryrun to dockerng.sls_build.
- Update dockerng minimal version requirements.
- Fix format error in error parsing.
- Keep fix for migrating salt home directory. (bsc#1022562)
- Fix salt pkg.latest raises exception if package is not available. (bsc#1012999)
- Timezone should always be in UTC. (bsc#1017078)
- Fix timezone handling for rpm installtime. (bsc#1017078)
- Increasing timeouts for running integrations tests.
- Add buildargs option to dockerng.build module.
- Fix error when missing ssh-option parameter.
- Re-add yum notify plugin.
- All kwargs to dockerng.create to provide all features to sls_build as well.
- Datetime should be returned always in UTC.
- Fix possible crash while deserialising data on infinite recursion in scheduled state. (bsc#1036125)
- Documentation refresh to 2016.11.4
- For a detailed description, please refer to:
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]");

  script_tag(name:"affected", value:"'Salt' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.4~42.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.4~42.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.4~42.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.4~42.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.4~42.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.4~42.2", rls:"SLES11.0SP4"))) {
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
