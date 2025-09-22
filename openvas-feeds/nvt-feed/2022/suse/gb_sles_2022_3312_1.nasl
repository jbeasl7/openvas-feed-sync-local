# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3312.1");
  script_cve_id("CVE-2020-14370", "CVE-2020-15157", "CVE-2021-20199", "CVE-2021-20291", "CVE-2021-3602");
  script_tag(name:"creation_date", value:"2022-09-20 04:49:26 +0000 (Tue, 20 Sep 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-06 17:06:32 +0000 (Tue, 06 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3312-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3312-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223312-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189893");
  script_xref(name:"URL", value:"https://github.com/containers/podman/issues/10606");
  script_xref(name:"URL", value:"https://github.com/containers/podman/issues/10682");
  script_xref(name:"URL", value:"https://github.com/containers/podman/issues/10929");
  script_xref(name:"URL", value:"https://github.com/containers/podman/issues/9731");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-September/012287.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcontainers-common' package(s) announced via the SUSE-SU-2022:3312-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libcontainers-common fixes the following issues:

libcontainers-common was updated:

- common component was updated to 0.44.0.
- storage component was updated to 1.36.0.
- image component was updated to 5.16.0.
- podman component was updated to 3.3.1.

3.3.1:

Bugfixes:

- Fixed a bug where unit files created by `podman generate systemd` could not cleanup shut down containers when stopped by `systemctl stop` .
- Fixed a bug where `podman machine` commands would not properly locate the `gvproxy` binary in some circumstances.
- Fixed a bug where containers created as part of a pod using the `--pod-id-file` option would not join the pod's network namespace .
- Fixed a bug where Podman, when using the systemd cgroups driver, could sometimes leak dbus sessions.
- Fixed a bug where the `until` filter to `podman logs` and `podman events` was improperly handled, requiring input to be negated .
- Fixed a bug where rootless containers using CNI networking run on systems using `systemd-resolved` for DNS would fail to start if resolved symlinked `/etc/resolv.conf` to an absolute path .

API:

- A large number of potential file descriptor leaks from improperly closing client connections have been fixed.

3.3.0:

Features:

- Containers inside VMs created by `podman machine` will now automatically handle port forwarding - containers in `podman machine` VMs that publish ports via `--publish` or `--publish-all` will have these ports not just forwarded on the VM, but also on the host system.
- The `podman play kube` command's `--network` option now accepts advanced network options (e.g. `--network slirp4netns:port_handler=slirp4netns`) .
- The `podman play kube` commmand now supports Kubernetes liveness probes, which will be created as Podman healthchecks.
- Podman now provides a systemd unit, `podman-restart.service`, which, when enabled, will restart all containers that were started with `--restart=always` after the system reboots.
- Rootless Podman can now be configured to use CNI networking by default by using the `rootless_networking` option in `containers.conf`.
- Images can now be pulled using `image:tag@digest` syntax (e.g. `podman pull fedora:34@sha256:1b0d4ddd99b1a8c8a80e885aafe6034c95f266da44ead992aab388e6aa91611a`) .
- The `podman container checkpoint` and `podman container restore` commands can now be used to checkpoint containers that are in pods, and restore those containers into pods.
- The `podman container restore` command now features a new option, `--publish`, to change the ports that are forwarded to a container that is being restored from an exported checkpoint.
- The `podman container checkpoint` command now features a new option, `--compress`, to specify the compression algorithm that will be used on the generated checkpoint.
- The `podman pull` command can now pull multiple images at once (e.g. `podman pull fedora:34 ubi8:latest` will pull both ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libcontainers-common' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libcontainers-common", rpm:"libcontainers-common~20210626~150100.3.15.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libcontainers-common", rpm:"libcontainers-common~20210626~150100.3.15.1", rls:"SLES15.0SP2"))) {
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
