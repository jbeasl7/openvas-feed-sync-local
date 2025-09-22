# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.4297.1");
  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2018-7187");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:32 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-13 15:09:52 +0000 (Tue, 13 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:4297-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:4297-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20184297-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, docker and go' package(s) announced via the SUSE-SU-2018:4297-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker and go fixes the following issues:

containerd and docker:
Add backport for building containerd (bsc#1102522, bsc#1113313)

Upgrade to containerd v1.1.2, which is required for Docker v18.06.1-ce.
 (bsc#1102522)

Enable seccomp support on SLE12 (fate#325877)

Update to containerd v1.1.1, which is the required version for the
 Docker v18.06.0-ce upgrade. (bsc#1102522)

Put containerd under the podruntime slice (bsc#1086185)

3rd party registries used the default Docker certificate (bsc#1084533)

Handle build breakage due to missing 'export GOPATH' (caused by
 resolution of boo#1119634). I believe Docker is one of the only packages
 with this problem.

go:
golang: arbitrary command execution via VCS path (bsc#1081495,
 CVE-2018-7187)

Make profile.d/go.sh no longer set GOROOT=, in order to make switching
 between versions no longer break. This ends up removing the need for
 go.sh entirely (because GOPATH is also set automatically) (boo#1119634)

Fix a regression that broke go get for import path patterns containing
 '...' (bsc#1119706)

Additionally, the package go1.10 has been added.");

  script_tag(name:"affected", value:"'containerd, docker and go' package(s) on SUSE Linux Enterprise Module for Containers 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.1.2~5.3.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~18.06.1_ce~6.8.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~18.06.1_ce~6.8.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~18.06.1_ce~6.8.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~18.06.1_ce~6.8.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2664_3ac297bc7fd0~4.3.5", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2664_3ac297bc7fd0~4.3.5", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc5+gitr3562_69663f0bd4b6~6.3.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc5+gitr3562_69663f0bd4b6~6.3.4", rls:"SLES15.0"))) {
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
