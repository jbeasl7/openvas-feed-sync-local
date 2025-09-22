# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3378.1");
  script_cve_id("CVE-2020-14370");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-29 18:33:51 +0000 (Tue, 29 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3378-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3378-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203378-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman' package(s) announced via the SUSE-SU-2020:3378-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podman fixes the following issues:

Security issue fixed:

This release resolves CVE-2020-14370, in which environment variables
 could be leaked between containers created using the Varlink API
 (bsc#1176804).

Non-security issues fixed:

add dependency to timezone package or podman fails to build a container
 (bsc#1178122)

Install new auto-update system units

Update to v2.1.1 (bsc#1178392):
 * Changes
 - The `podman info` command now includes the cgroup manager Podman is
 using.
 * API
 - The REST API now includes a Server header in all responses.
 - Fixed a bug where the Libpod and Compat Attach endpoints could
 terminate early, before sending all output from the container.
 - Fixed a bug where the Compat Create endpoint for containers did not
 properly handle the Interactive parameter.
 - Fixed a bug where the Compat Kill endpoint for containers could
 continue to run after a fatal error.
 - Fixed a bug where the Limit parameter of the Compat List endpoint
 for Containers did not properly handle a limit of 0 (returning
 nothing, instead of all containers) [#7722].
 - The Libpod Stats endpoint for containers is being deprecated and
 will be replaced by a similar endpoint with additional features in a
 future release.

Changes in v2.1.0
 * Features
 - A new command, `podman image mount`, has been added. This allows for
 an image to be mounted, read-only, to inspect its contents without
 creating a container from it [#1433].
 - The `podman save` and `podman load` commands can now create and load
 archives containing multiple images [#2669].
 - Rootless Podman now supports all `podman network` commands, and
 rootless containers can now be joined to networks.
 - The performance of `podman build` on `ADD` and `COPY` instructions
 has been greatly improved, especially when a `.dockerignore` is
 present.
 - The `podman run` and `podman create` commands now support a new mode
 for the `--cgroups` option, `--cgroups=split`. Podman will create
 two cgroups under the cgroup it was launched in, one for the
 container and one for Conmon. This mode is useful for running Podman
 in a systemd unit, as it ensures that all processes are retained in
 systemd's cgroup hierarchy [#6400].
 - The `podman run` and `podman create` commands can now specify
 options to slirp4netns by using the `--network` option as follows:
`--net slirp4netns:opt1,opt2`. This allows for, among other things,
switching the port forwarder used by slirp4netns away from rootlessport.
 - The `podman ps` command now features a new option, `--storage`, to
 show containers from Buildah, CRI-O and other applications.
 - The `podman run` and `podman create` commands now feature a
 `--sdnotify` option to control the behavior of systemd's sdnotify
 with containers, enabling improved support for Podman in
 `Type=notify` units.
 - The `podman run` command now features a `--preserve-fds`
 opton to pass file ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'podman' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise Module for Containers 15-SP1, SUSE Linux Enterprise Module for Containers 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~2.1.1~4.28.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~2.1.1~4.28.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~2.1.1~4.28.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-cni-config", rpm:"podman-cni-config~2.1.1~4.28.1", rls:"SLES15.0SP2"))) {
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
