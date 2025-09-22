# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0697.1");
  script_cve_id("CVE-2019-18466");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-30 14:17:15 +0000 (Wed, 30 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0697-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0697-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200697-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cni, cni-plugins, conmon, fuse-overlayfs, podman' package(s) announced via the SUSE-SU-2020:0697-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cni, cni-plugins, conmon, fuse-overlayfs, podman fixes the following issues:

podman was updated to 1.8.0:
CVE-2019-18466: Fixed a bug where podman cp would improperly copy files
 on the host when copying a symlink in the container that included a glob
 operator (#3829 bsc#1155217)
The name of the cni-bridge in the default config changed from 'cni0' to
 'podman-cni0' with podman-1.6.0. Add a %trigger to rename the bridge in
 the system to the new default if it exists. The trigger is only excuted
 when updating podman-cni-config from something older than 1.6.0. This is
 mainly needed for SLE where we're updating from 1.4.4 to 1.8.0
 (bsc#1160460).

Update podman to v1.8.0 (bsc#1160460):
Features

 - The podman system service command has been added, providing a preview
 of Podman's new Docker-compatible API. This API is still very new, and
 not yet ready for production use, but is available for early testing
 - Rootless Podman now uses Rootlesskit for port forwarding, which should
 greatly improve performance and capabilities
 - The podman untag command has been added to remove tags from images
 without deleting them
 - The podman inspect command on images now displays previous names they
 used
 - The podman generate systemd command now supports a --new
 option to generate service files that create and run new containers
 instead of managing existing containers
 - Support for --log-opt tag= to set logging tags has been added to the
 journald log driver
 - Added support for using Seccomp profiles embedded in images for podman
 run and podman create via the new --seccomp-policy CLI flag
 - The podman play kube command now honors pull policy Bugfixes

 - Fixed a bug where the podman cp command would not copy the contents of
 directories when paths ending in /. were given
 - Fixed a bug where the podman play kube command did not properly locate
 Seccomp profiles specified relative to localhost
 - Fixed a bug where the podman info command for remote Podman did not
 show registry information
 - Fixed a bug where the podman exec command did not support having input
 piped into it
 - Fixed a bug where the podman cp command with rootless Podman
 on CGroups v2 systems did not properly determine if the container
 could be paused while copying
 - Fixed a bug where the podman container prune --force command could
 possible remove running containers if they were started while the
 command was running
 - Fixed a bug where Podman, when run as root, would not properly
 configure slirp4netns networking when requested
 - Fixed a bug where podman run --userns=keep-id did not work when the
 user had a UID over 65535
 - Fixed a bug where rootless podman run and podman create with the
 --userns=keep-id option could change permissions on /run/user/$UID and
 break KDE
 - Fixed a bug where rootless Podman could not be run in a systemd
 service on systems using CGroups v2
 - Fixed a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cni, cni-plugins, conmon, fuse-overlayfs, podman' package(s) on SUSE Linux Enterprise Module for Containers 15-SP1, SUSE Linux Enterprise Module for Public Cloud 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"cni", rpm:"cni~0.7.1~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cni-plugins", rpm:"cni-plugins~0.8.4~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.0.10~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.0.10~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs", rpm:"fuse-overlayfs~0.7.6~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs-debuginfo", rpm:"fuse-overlayfs-debuginfo~0.7.6~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fuse-overlayfs-debugsource", rpm:"fuse-overlayfs-debugsource~0.7.6~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~1.8.0~4.14.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~1.8.0~4.14.1", rls:"SLES15.0SP1"))) {
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
