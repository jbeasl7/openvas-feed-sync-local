# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20095.1");
  script_cve_id("CVE-2025-54388");
  script_tag(name:"creation_date", value:"2026-01-26 08:39:16 +0000 (Mon, 26 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-08 16:34:31 +0000 (Mon, 08 Sep 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20095-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20095-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620095-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250508");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/28/#2833");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/28/#2840");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/28/#2850");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/28/#2851");
  script_xref(name:"URL", value:"https://github.com/docker/buildx/releases/tag/v0.26.0");
  script_xref(name:"URL", value:"https://github.com/docker/buildx/releases/tag/v0.26.1");
  script_xref(name:"URL", value:"https://github.com/docker/buildx/releases/tag/v0.28.0");
  script_xref(name:"URL", value:"https://github.com/docker/buildx/releases/tag/v0.29.0");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023886.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the SUSE-SU-2026:20095-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker fixes the following issues:

Changes in docker:

- Update to Docker 28.5.1-ce. See upstream changelog online at
 <[link moved to references]>

- Update to Docker 28.5.0-ce. See upstream changelog online at
 <[link moved to references]>

- Update to docker-buildx v0.29.0. Upstream changelog:
 <[link moved to references]>

- Remove git-core recommends on SLE. Most SLE systems have
 installRecommends=yes by default and thus end up installing git with Docker.
 bsc#1250508

 This feature is mostly intended for developers ('docker build git://') so
 most users already have the dependency installed, and the error when git is
 missing is fairly straightforward (so they can easily figure out what they
 need to install).

- Update to docker-buildx v0.28.0. Upstream changelog:
 <[link moved to references]>

- Update to Docker 28.4.0-ce. See upstream changelog online at
 <[link moved to references]>
 * Fixes a nil pointer panic in 'docker push'. bsc#1248373

- Update warnings and errors related to 'docker buildx ...' so that they
 reference our openSUSE docker-buildx packages.

- Enable building docker-buildx for SLE15 systems with SUSEConnect secret
 injection enabled. PED-12534 PED-8905 bsc#1247594

 As docker-buildx does not support our SUSEConnect secret injection (and some
 users depend 'docker build' working transparently), patch the docker CLI so
 that 'docker build' will no longer automatically call 'docker buildx build',
 effectively making DOCKER_BUILDKIT=0 the default configuration. Users can
 manually use 'docker buildx ...' commands or set DOCKER_BUILDKIT=1 in order
 to opt-in to using docker-buildx.

 Users can silence the 'docker build' warning by setting DOCKER_BUILDKIT=0
 explicitly.

 In order to inject SCC credentials with docker-buildx, users should use

 RUN --mount=type=secret,id=SCCcredentials zypper -n ...

 in their Dockerfiles, and

 docker buildx build --secret id=SCCcredentials,src=/etc/zypp/credentials.d/SCCcredentials,type=file .

 when doing their builds.

- Update to Docker 28.3.3-ce. See upstream changelog online at
 <[link moved to references]>
 CVE-2025-54388 bsc#1247367

- Update to docker-buildx v0.26.1. Upstream changelog:
 <[link moved to references]>

- Update to docker-buildx v0.26.0. Upstream changelog:
 <[link moved to references]>");

  script_tag(name:"affected", value:"'docker' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~28.5.1_ce~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~28.5.1_ce~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-buildx", rpm:"docker-buildx~0.29.0~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~28.5.1_ce~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-rootless-extras", rpm:"docker-rootless-extras~28.5.1_ce~160000.4.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~28.5.1_ce~160000.4.1", rls:"SLES16.0.0"))) {
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
