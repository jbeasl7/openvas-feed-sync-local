# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0103.1");
  script_cve_id("CVE-2022-27664", "CVE-2025-22868");
  script_tag(name:"creation_date", value:"2025-03-26 07:47:44 +0000 (Wed, 26 Mar 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-09 03:04:26 +0000 (Fri, 09 Sep 2022)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0103-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0103-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4JTZ2DTLVURMW7SOEALLXE6GW75RG2MM/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239291");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cadvisor' package(s) announced via the openSUSE-SU-2025:0103-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cadvisor fixes the following issues:

- update to 0.52.1:

 * Make resctrl optional/pluggable

- update to 0.52.0:

 * bump containerd related deps: api v1.8.0, errdefs v1.0.0, ttrpc v1.2.6
 * chore: Update Prometheus libraries
 * bump runc to v1.2.4
 * Add Pressure Stall Information Metrics
 * Switch to opencontainers/cgroups repository (includes update
 from golang 1.22 to 1.24)
 * Bump to newer opencontainers/image-spec @ v1.1.1

- update to 0.49.2:

 * Cp fix test
 * Revert 'reduce_logs_for_kubelet_use_crio'

 - CVE-2025-22868: golang.org/x/oauth2/jws: Unexpected memory consumption during token parsing in golang.org/x/oauth2 (boo#1239291)

- Update to version 0.49.1:

 * build docker - add --provenance=false flag
 * Remove s390x support
 * Disable libipmctl in build
 * Ugrade base image to 1.22 and alpine 3.18
 * fix type of C.malloc in cgo
 * Bump runc to v1.1.12
 * Bump to bullseye
 * Remove section about canary image
 * Add note about WebUI auth
 * Remove mentions of accelerator from the docs
 * reduce_logs_for_kubelet_use_crio
 * upgrade actions/checkout and actions/setup-go and actions/upload-artifact
 * build(deps): bump golang.org/x/crypto from 0.14.0 to 0.17.0 in /cmd
 * add cadvisor and crio upstream changes
 * Avoid using container/podman in manager.go
 * container: skip checking for files in non-existent directories.
 * Adjust the log level of Initialize Plugins
 * add ignored device
 * fix: variable naming
 * build(deps): bump golang.org/x/net from 0.10.0 to 0.17.0 in /cmd
 * manager: require higher verbosity level for container info misses
 * Information should be logged on increased verbosity only
 * Running do mod tidy
 * Running go mod tidy
 * Running go mod tidy
 * container/libcontainer: Improve limits file parsing perf
 * container/libcontainer: Add limit parsing benchmark
 * build(deps): bump github.com/cyphar/filepath-securejoin in /cmd
 * build(deps): bump github.com/cyphar/filepath-securejoin
 * Set verbosity after flag definition
 * fix: error message typo
 * vendor: bump runc to 1.1.9
 * Switch to use busybox from registry.k8s.io
 * Bump golang ci lint to v1.54.1
 * Bump github.com/docker/docker in /cmd
 * Bump github.com/docker/docker
 * Bump github.com/docker/distribution in /cmd
 * Bump github.com/docker/distribution
 * Update genproto dependency to isolated submodule
 * remove the check for the existence of NFS files, which will cause unnecessary requests.
 * reduce inotify watch
 * fix performance degradation of NFS
 * fix: fix type issue
 * fix: fix cgo memory leak
 * ft: export memory kernel usage
 * sysinfo: Ignore 'hidden' sysfs device entries
 * Increasing required verbosity level
 * Patch to fix issue 2341
 * podman support: Enable Podman support.
 * podman support: Create Podman handler.
 * podman support: Changes in Docker handler.
 * unit test: machine_swap_bytes
 * Add documentation for machine_swap_bytes ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cadvisor' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cadvisor", rpm:"cadvisor~0.52.1~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
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
