# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.4319.1");
  script_cve_id("CVE-2023-45142", "CVE-2023-47108", "CVE-2024-41110");
  script_tag(name:"creation_date", value:"2024-12-16 09:14:15 +0000 (Mon, 16 Dec 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-10 19:15:16 +0000 (Fri, 10 Nov 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:4319-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4319-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244319-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233819");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/26.1/#2610");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/26.1/#2614");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/26.1/#2615");
  script_xref(name:"URL", value:"https://github.com/docker/buildx/releases/tag/v0.17.1");
  script_xref(name:"URL", value:"https://github.com/docker/buildx/releases/tag/v0.18.0");
  script_xref(name:"URL", value:"https://github.com/docker/buildx/releases/tag/v0.19.0");
  script_xref(name:"URL", value:"https://github.com/docker/buildx/releases/tag/v0.19.2");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/020003.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the SUSE-SU-2024:4319-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker fixes the following issues:

- Update docker-buildx to v0.19.2. See upstream changelog online at
 <[link moved to references]>.

 Some notable changelogs from the last update:
 * <[link moved to references]>
 * <[link moved to references]>

- Add a new toggle file /etc/docker/suse-secrets-enable which allows users to
 disable the SUSEConnect integration with Docker (which creates special mounts
 in /run/secrets to allow container-suseconnect to authenticate containers
 with registries on registered hosts). bsc#1231348 bsc#1232999

 In order to disable these mounts, just do

 echo 0 > /etc/docker/suse-secrets-enable

 and restart Docker. In order to re-enable them, just do

 echo 1 > /etc/docker/suse-secrets-enable

 and restart Docker. Docker will output information on startup to tell you
 whether the SUSE secrets feature is enabled or not.

- Disable docker-buildx builds for SLES. It turns out that build containers
 with docker-buildx don't currently get the SUSE secrets mounts applied,
 meaning that container-suseconnect doesn't work when building images.
 bsc#1233819

- Remove DOCKER_NETWORK_OPTS from docker.service. This was removed from
 sysconfig a long time ago, and apparently this causes issues with systemd in
 some cases.

- Allow a parallel docker-stable RPM to exists in repositories.

- Update to docker-buildx v0.17.1 to match standalone docker-buildx package we
 are replacing. See upstream changelog online at
 <[link moved to references]>

- Allow users to disable SUSE secrets support by setting
 DOCKER_SUSE_SECRETS_ENABLE=0 in /etc/sysconfig/docker. (bsc#1231348)

- Mark docker-buildx as required since classic 'docker build' has been
 deprecated since Docker 23.0. (bsc#1230331)

- Import docker-buildx v0.16.2 as a subpackage. Previously this was a separate
 package, but with docker-stable it will be necessary to maintain the packages
 together and it makes more sense to have them live in the same OBS package.
 (bsc#1230333)

- Update to Docker 26.1.5-ce. See upstream changelog online at
 <[link moved to references]>
 bsc#1230294

- This update includes fixes for:
 * CVE-2024-41110. bsc#1228324
 * CVE-2023-47108. bsc#1217070 bsc#1229806
 * CVE-2023-45142. bsc#1228553 bsc#1229806

- Update to Docker 26.1.4-ce. See upstream changelog online at
 <[link moved to references]>

- Update to Docker 26.1.0-ce. See upstream changelog online at
 <[link moved to references]>

- Update --add-runtime to point to correct binary path.");

  script_tag(name:"affected", value:"'docker' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~26.1.5_ce~98.120.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~26.1.5_ce~98.120.1", rls:"SLES12.0SP5"))) {
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
