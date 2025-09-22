# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3084.1");
  script_cve_id("CVE-2016-8867");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:02 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-28 20:04:37 +0000 (Fri, 28 Oct 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3084-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3084-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163084-1/");
  script_xref(name:"URL", value:"https://github.com/docker/docker/releases/tag/v1.12.3");
  script_xref(name:"URL", value:"https://github.com/docker/docker/blob/v1.12.2/CHANGELOG.md");
  script_xref(name:"URL", value:"https://github.com/docker/docker/releases/tag/v1.12.1");
  script_xref(name:"URL", value:"https://github.com/docker/docker/releases/tag/v1.12.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Docker and dependencies' package(s) announced via the SUSE-SU-2016:3084-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Docker and its dependencies fixes the following issues:
- fix runc and containerd revisions (bsc#1009961)
docker:
- Updates version 1.11.2 to 1.12.3 (bsc#1004490, bsc#996015, bsc#995058)
- Fix ambient capability usage in containers (bsc#1007249, CVE-2016-8867)
- Change the internal mountpoint name to not use ':' as that character can
 be considered a special character by other tools. (bsc#999582)
- Add dockerd(8) man page.
- Package docker-proxy (which was split out of the docker binary in 1.12).
 (bsc#995620)
- Docker 'migrator' prevents installing 'docker', if docker 1.9 was
 installed before but there were no images. (bsc#995102)
- Specify an 'OCI' runtime for our runc package explicitly. (bsc#978260)
- Use gcc6-go instead of gcc5-go (bsc#988408)
For a detailed description of all fixes and improvements, please refer to:
[link moved to references] [link moved to references] [link moved to references] [link moved to references] containerd:
- Update to current version required from Docker 1.12.3.
- Add missing Requires(post): %fillup_prereq. (bsc#1006368)
- Use gcc6-go instead of gcc5-go. (bsc#988408)
runc:
- Update to current version required from Docker 1.12.3.
- Use gcc6-go instead of gcc5-go. (bsc#988408)
rubygem-excon:
- Updates version from 0.39.6 to 0.52.0.
For a detailed description of all fixes and improvements, please refer to the installed changelog.txt.
rubygem-docker-api:
- Updated version from 1.17.0 to 1.31.0.");

  script_tag(name:"affected", value:"'Docker and dependencies' package(s) on SUSE Linux Enterprise Module for Containers 12, SUSE OpenStack Cloud 6.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~0.2.4+gitr565_0366d7e~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-debuginfo", rpm:"containerd-debuginfo~0.2.4+gitr565_0366d7e~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-debugsource", rpm:"containerd-debugsource~0.2.4+gitr565_0366d7e~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~1.12.3~81.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~1.12.3~81.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~1.12.3~81.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-rubygem-docker-api", rpm:"ruby2.1-rubygem-docker-api~1.31.0~11.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-rubygem-excon", rpm:"ruby2.1-rubygem-excon~0.52.0~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~0.1.1+gitr2816_02f8fa7~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo", rpm:"runc-debuginfo~0.1.1+gitr2816_02f8fa7~9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debugsource", rpm:"runc-debugsource~0.1.1+gitr2816_02f8fa7~9.1", rls:"SLES12.0"))) {
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
