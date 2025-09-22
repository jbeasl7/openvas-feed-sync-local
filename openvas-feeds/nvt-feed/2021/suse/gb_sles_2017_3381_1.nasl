# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3381.1");
  script_cve_id("CVE-2017-14695", "CVE-2017-14696");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:50 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-14 21:49:19 +0000 (Tue, 14 Nov 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3381-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3381-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173381-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985112");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-December/003543.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Salt' package(s) announced via the SUSE-SU-2017:3381-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes one security issue and bugs.

The following security issues have been fixed:

- CVE-2017-14695: A directory traversal vulnerability in minion id validation allowed remote minions with incorrect
 credentials to authenticate to a master via a crafted minion ID. (bsc#1062462)
- CVE-2017-14696: It was possible to force a remote Denial of Service with a specially crafted authentication
 request. (bsc#1062464)

Additionally, the following non-security issues have been fixed:

- Removed deprecation warning for beacon configuration using dictionaries. (bsc#1041993)
- Fixed beacons failure when pillar-based suppressing config-based. (bsc#1060230)
- Fixed minion resource exhaustion when many functions are being executed in parallel. (bsc#1059758)
- Remove 'TasksTask' attribute from salt-master.service in older versions of systemd. (bsc#985112)
- Fix for delete_deployment in Kubernetes module. (bsc#1059291)
- Catching error when PIDfile cannot be deleted. (bsc#1050003)
- Use $HOME to get the user home directory instead using '~' char. (bsc#1042749)");

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

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.4~43.10.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.4~43.10.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.4~43.10.2", rls:"SLES11.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~2016.11.4~43.10.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2016.11.4~43.10.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2016.11.4~43.10.2", rls:"SLES11.0SP4"))) {
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
