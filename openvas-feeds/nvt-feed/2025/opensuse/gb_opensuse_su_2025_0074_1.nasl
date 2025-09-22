# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0074.1");
  script_cve_id("CVE-2024-21626", "CVE-2025-24965");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 15:38:09 +0000 (Fri, 09 Feb 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0074-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0074-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MFFSKUX256PEK52RLQGT33MIN3ZQO27D/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237421");
  script_xref(name:"URL", value:"https://github.com/containers/crun/releases/tag/1.18");
  script_xref(name:"URL", value:"https://github.com/containers/crun/releases/tag/1.18.2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'crun' package(s) announced via the openSUSE-SU-2025:0074-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for crun fixes the following issues:

Update to 1.20:

 * krun: fix CVE-2025-24965. The .krun_config.json file could be created outside of the container rootfs. (bsc#1237421)
 * cgroup: reverted the removal of tun/tap from the default allow list, this was done in crun-1.5. The tun/tap device is now added by default again.
 * CRIU: do not set network_lock unless explicitly specified.
 * status: disallow container names containing slashes in their name.
 * linux: Improved error message when failing to set the net.ipv4.ping_group_range sysctl.
 * scheduler: Ignore ENOSYS errors when resetting the CPU affinity mask.
 * linux: return a better error message when pidfd_open fails with EINVAL.
 * cgroup: display the absolute path to cgroup.controllers when a controller is unavailable.
 * exec: always call setsid. Now processes created through exec get the correct process group id.

Update to 1.19.1:

 * linux: fix a hang if there are no reads from the tty. Use non blocking
 sockets to read and write from the tty so that the 'crun exec' process
 doesn't hang when the terminal is not consuming any data.
 * linux: remove the workaround needed to mount a cgroup on top of
 another cgroup mount. The workaround had the disadvantage to temporarily
 leak a mount on the host. The alternative that is currently used is
 to mount a temporary tmpfs between the twoo cgroup mounts.

Update to 1.19:
 * wasm: add new handler wamr.
 * criu: allow passing network lock method to libcriu.
 * linux: honor exec cpu affinity mask.
 * build: fix build with musl libc.
 * crun: use mount API to self-clone.
 * cgroup, systemd: do not override devices on update. If the 'update' request has no device block configured, do not reset the previously configuration.
 * cgroup: handle case where cgroup v1 freezer is disabled. On systems without the freezer controller, containers were mistakenly reported as paused.
 * cgroup: do not stop process on exec. The cpu mask is configured on the systemd scope, the previous workaround to stop the container until the cgroup is fully configured is no longer needed.

- Update to crun v1.18.2 Upstream changelog is available from
 <[link moved to references]>

- Update to crun v1.18. Upstream changelog is available from
 <[link moved to references]>

Update to 1.17:

 * Add --log-level option. It accepts error, warning and error.
 * Add debug logs for container creation.
 * Fix double-free in crun exec code that could lead to a crash.
 * Allow passing an ID to the journald log driver.
 * Report 'executable not found' errors after tty has been setup.
 * Do not treat EPIPE from hooks as an error.
 * Make sure DefaultDependencies is correctly set in the systemd scope.
 * Improve the error message when the container process is not found.
 * Improve error handling for the mnt namespace restoration.
 * Fix error handling for getpwuid_r, recvfrom and libcrun_kill_linux.
 * ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'crun' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"crun", rpm:"crun~1.20~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
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
