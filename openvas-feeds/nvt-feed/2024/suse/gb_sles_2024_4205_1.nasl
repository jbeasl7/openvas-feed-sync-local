# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.4205.1");
  script_cve_id("CVE-2024-41110");
  script_tag(name:"creation_date", value:"2024-12-06 04:27:28 +0000 (Fri, 06 Dec 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:4205-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4205-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244205-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231348");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/24.0/#2409");
  script_xref(name:"URL", value:"https://github.com/docker/buildx/releases/tag/v0.17.1");
  script_xref(name:"URL", value:"https://github.com/moby/buildkit/pull/4896");
  script_xref(name:"URL", value:"https://github.com/moby/buildkit/pull/5060");
  script_xref(name:"URL", value:"https://github.com/moby/moby/pull/48034");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/019929.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-stable' package(s) announced via the SUSE-SU-2024:4205-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker-stable fixes the following issues:

- Remove DOCKER_NETWORK_OPTS from docker.service. This was removed from
 sysconfig a long time ago, and apparently this causes issues with systemd in
 some cases.
- Update --add-runtime to point to correct binary path.

- Further merge docker and docker-stable specfiles to minimise the differences.
 The main thing is that we now include both halves of the
 Conflicts/Provides/Obsoletes dance in both specfiles.

- Update to docker-buildx v0.17.1 to match standalone docker-buildx package we
 are replacing. See upstream changelog online at
 <[link moved to references]>

- Allow users to disable SUSE secrets support by setting
 DOCKER_SUSE_SECRETS_ENABLE=0 in /etc/sysconfig/docker. bsc#1231348

- Import specfile changes for docker-buildx as well as the changes to help
 reduce specfile differences between docker-stable and docker. bsc#1230331
 bsc#1230333

- Backport patch for CVE-2024-41110. bsc#1228324

- Initial docker-stable release, forked from Docker 24.0.6-ce release
 (packaged on 2023-10-11).

- Update to Docker 24.0.9-ce, which is the latest version of the 24.0.x branch.
 It seems likely this will be the last upstream version of the 24.0.x branch
 (it seems Mirantis is going to do LTS for 23.0.x, not 24.0.x).
 <[link moved to references]>
- Fix BuildKit's symlink resolution logic to correctly handle non-lexical
 symlinks. Backport of <[link moved to references]> and
 <[link moved to references]>. bsc#1221916
- Write volume options atomically so sudden system crashes won't result in
 future Docker starts failing due to empty files. Backport of
 <[link moved to references]>. bsc#1214855");

  script_tag(name:"affected", value:"'docker-stable' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"docker-stable", rpm:"docker-stable~24.0.9_ce~1.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-bash-completion", rpm:"docker-stable-bash-completion~24.0.9_ce~1.5.1", rls:"SLES12.0SP5"))) {
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
