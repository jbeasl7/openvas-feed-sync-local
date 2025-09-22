# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2223.1");
  script_cve_id("CVE-2018-15664", "CVE-2019-10152", "CVE-2019-6778");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-23 14:29:07 +0000 (Thu, 23 May 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2223-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2223-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192223-1/");
  script_xref(name:"URL", value:"https://github.com/containers/libpod/issues/3363");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman, slirp4netns and libcontainers-common' package(s) announced via the SUSE-SU-2019:2223-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a version update for podman to version 1.4.4 (bsc#1143386).

Additional changes by SUSE on top:
Remove fuse-overlayfs because it's (currently) an unsatisfied dependency
 on SLE (bsc#1143386)

Update libpod.conf to use correct infra_command

Update libpod.conf to use better versioned pause container

Update libpod.conf to use official kubic pause container

Update libpod.conf to match latest features set: detach_keys, lock_type,
 runtime_supports_json

Add podman-remote varlink client

Version update podman to v1.4.4:
Features

 - Podman now has greatly improved support for containers using multiple
 OCI runtimes. Containers now remember if they were created with a
 different runtime using --runtime and will always use that runtime
 - The cached and delegated options for volume mounts are now allowed for
 Docker compatability (#3340)
 - The podman diff command now supports the --latest flag Bugfixes

 - Fixed a bug where rootless Podman would attempt to use the entire root
 configuration if no rootless configuration was present for the user,
 breaking rootless Podman for new installations
 - Fixed a bug where rootless Podman's pause process would block SIGTERM,
 preventing graceful system shutdown and hanging until the system's
 init send SIGKILL
 - Fixed a bug where running Podman as root with sudo -E would not work
 after running rootless Podman at least once
 - Fixed a bug where options for tmpfs volumes added with the --tmpfs
 flag were being ignored
 - Fixed a bug where images with no layers could not properly be
 displayed and removed by Podman
 - Fixed a bug where locks were not properly freed on failure to create a
 container or pod
 - Fixed a bug where podman cp on a single file would create a directory
 at the target and place the file in it (#3384)
 - Fixed a bug where podman inspect --format '{{.Mounts}}' would print a
 hexadecimal address instead of a container's mounts
 - Fixed a bug where rootless Podman would not add an entry to
 container's /etc/hosts files for their own hostname (#3405)
 - Fixed a bug where podman ps --sync would segfault (#3411)
 - Fixed a bug where podman generate kube would produce an invalid ports
 configuration (#3408)
Misc

 - Updated containers/storage to v1.12.13
 - Podman now performs much better on systems with heavy I/O load
 - The --cgroup-manager flag to podman now shows the correct default
 setting in help if the default was overridden by libpod.conf
 - For backwards compatability, setting --log-driver=json-file in podman
 run is now supported as an alias for --log-driver=k8s-file. This is
 considered deprecated, and json-file will be moved to a new
 implementation in the future
 ([#3363]([link moved to references] d/issues/3363))
 - Podman's default libpod.conf file now allows the crun OCI runtime to
 be used if it is installed

Update podman to v1.4.2:
Fixed a bug where Podman could not run containers ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'podman, slirp4netns and libcontainers-common' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Containers 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libcontainers-common", rpm:"libcontainers-common~20190401~3.3.5", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs", rpm:"fuse-overlayfs~0.4.1~3.3.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs-debuginfo", rpm:"fuse-overlayfs-debuginfo~0.4.1~3.3.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs-debugsource", rpm:"fuse-overlayfs-debugsource~0.4.1~3.3.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse3", rpm:"fuse3~3.6.1~3.3.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse3-debuginfo", rpm:"fuse3-debuginfo~3.6.1~3.3.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse3-debugsource", rpm:"fuse3-debugsource~3.6.1~3.3.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfuse3-3", rpm:"libfuse3-3~3.6.1~3.3.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfuse3-3-debuginfo", rpm:"libfuse3-3-debuginfo~3.6.1~3.3.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~1.4.4~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~1.4.4~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slirp4netns", rpm:"slirp4netns~0.3.0~3.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slirp4netns-debuginfo", rpm:"slirp4netns-debuginfo~0.3.0~3.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slirp4netns-debugsource", rpm:"slirp4netns-debugsource~0.3.0~3.3.3", rls:"SLES15.0SP1"))) {
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
