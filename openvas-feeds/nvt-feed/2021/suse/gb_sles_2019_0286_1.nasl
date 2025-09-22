# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0286.1");
  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:31 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-04 15:22:35 +0000 (Mon, 04 Feb 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0286-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0286-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190286-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the SUSE-SU-2019:0286-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, docker-runc and golang-github-docker-libnetwork fixes the following issues:

Security issues fixed for containerd, docker, docker-runc and golang-github-docker-libnetwork:
CVE-2018-16873: cmd/go: remote command execution during 'go get -u'
 (bsc#1118897)

CVE-2018-16874: cmd/go: directory traversal in 'go get' via curly braces
 in import paths (bsc#1118898)

CVE-2018-16875: crypto/x509: CPU denial of service (bsc#1118899)

Non-security issues fixed for docker:
Disable leap based builds for kubic flavor (bsc#1121412)

Allow users to explicitly specify the NIS domainname of a container
 (bsc#1001161)

Update docker.service to match upstream and avoid rlimit problems
 (bsc#1112980)

Allow docker images larger then 23GB (bsc#1118990)

Docker version update to version 18.09.0-ce (bsc#1115464)");

  script_tag(name:"affected", value:"'docker' package(s) on SUSE Linux Enterprise Module for Containers 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.1.2~5.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~18.09.0_ce~6.11.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~18.09.0_ce~6.11.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~18.09.0_ce~6.11.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~18.09.0_ce~6.11.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2704_6da50d197830~4.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2704_6da50d197830~4.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc5+gitr3562_69663f0bd4b6~6.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc5+gitr3562_69663f0bd4b6~6.6.1", rls:"SLES15.0"))) {
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
