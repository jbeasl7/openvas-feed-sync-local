# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3423.1");
  script_cve_id("CVE-2019-10214", "CVE-2020-10696");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-01 13:18:14 +0000 (Wed, 01 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3423-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3423-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203423-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah' package(s) announced via the SUSE-SU-2020:3423-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah fixes the following issues:

buildah was updated to v1.17.0 (bsc#1165184):

Handle cases where other tools mount/unmount containers

overlay.MountReadOnly: support RO overlay mounts

overlay: use fusermount for rootless umounts

overlay: fix umount

Switch default log level of Buildah to Warn. Users need to see these
 messages

Drop error messages about OCI/Docker format to Warning level

build(deps): bump github.com/containers/common from 0.26.0 to 0.26.2

tests/testreport: adjust for API break in storage v1.23.6

build(deps): bump github.com/containers/storage from 1.23.5 to 1.23.7

build(deps): bump github.com/fsouza/go-dockerclient from 1.6.5 to 1.6.6

copier: put: ignore Typeflag='g'

Use curl to get repo file (fix #2714)

build(deps): bump github.com/containers/common from 0.25.0 to 0.26.0

build(deps): bump github.com/spf13/cobra from 1.0.0 to 1.1.1

Remove docs that refer to bors, since we're not using it

Buildah bud should not use stdin by default

bump containerd, docker, and golang.org/x/sys

Makefile: cross: remove windows.386 target

copier.copierHandlerPut: don't check length when there are errors

Stop excessive wrapping

CI: require that conformance tests pass

bump(github.com/openshift/imagebuilder) to v1.1.8

Skip tlsVerify insecure BUILD_REGISTRY_SOURCES

Fix build path wrong containers/podman#7993

refactor pullpolicy to avoid deps

build(deps): bump github.com/containers/common from 0.24.0 to 0.25.0

CI: run gating tasks with a lot more memory

ADD and COPY: descend into excluded directories, sometimes

copier: add more context to a couple of error messages

copier: check an error earlier

copier: log stderr output as debug on success

Update nix pin with make nixpkgs

Set directory ownership when copied with ID mapping

build(deps): bump github.com/sirupsen/logrus from 1.6.0 to 1.7.0

build(deps): bump github.com/containers/common from 0.23.0 to 0.24.0

Cirrus: Remove bors artifacts

Sort build flag definitions alphabetically

ADD: only expand archives at the right time

Remove configuration for bors

Shell Completion for podman build flags

Bump c/common to v0.24.0

New CI check: xref --help vs man pages

CI: re-enable several linters

Move --userns-uid-map/--userns-gid-map description into buildah man page

add: preserve ownerships and permissions on ADDed archives

Makefile: tweak the cross-compile target

Bump containers/common to v0.23.0

chroot: create bind mount targets 0755 instead of 0700

Change call to Split() to safer SplitN()

chroot: fix handling of errno seccomp rules

build(deps): bump github.com/containers/image/v5 from 5.5.2 to 5.6.0

Add In Progress section to contributing

integration tests: make sure tests run in ${topdir}/tests

Run(): ignore containers.conf's environment configuration

Warn when setting healthcheck in OCI format

Cirrus: Skip git-validate on branches

tools: update git-validation to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'buildah' package(s) on SUSE Linux Enterprise Module for Containers 15-SP1, SUSE Linux Enterprise Module for Containers 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.17.0~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.17.0~3.6.1", rls:"SLES15.0SP2"))) {
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
