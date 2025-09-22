# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3506.1");
  script_cve_id("CVE-2021-30465", "CVE-2021-32760", "CVE-2021-41089", "CVE-2021-41091", "CVE-2021-41092", "CVE-2021-41103");
  script_tag(name:"creation_date", value:"2021-10-26 06:38:18 +0000 (Tue, 26 Oct 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-14 19:38:38 +0000 (Thu, 14 Oct 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3506-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3506-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213506-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191434");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.0.0");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.0.0-rc94");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.0.0-rc95");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.0.1");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.0.2");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-October/009645.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, docker, runc' package(s) announced via the SUSE-SU-2021:3506-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, runc fixes the following issues:

Docker was updated to 20.10.9-ce. (bsc#1191355)

See upstream changelog in the packaged
 /usr/share/doc/packages/docker/CHANGELOG.md.

 CVE-2021-41092 CVE-2021-41089 CVE-2021-41091 CVE-2021-41103

container was updated to v1.4.11, to fix CVE-2021-41103. bsc#1191355

- CVE-2021-32760: Fixed that a archive package allows chmod of file outside of unpack target directory (bsc#1188282)

- Install systemd service file as well (bsc#1190826)

Update to runc v1.0.2. Upstream changelog is available from

 [link moved to references]

* Fixed a failure to set CPU quota period in some cases on cgroup v1.
* Fixed the inability to start a container with the 'adding seccomp filter
 rule for syscall ...' error, caused by redundant seccomp rules (i.e. those
 that has action equal to the default one). Such redundant rules are now
 skipped.
* Made release builds reproducible from now on.
* Fixed a rare debug log race in runc init, which can result in occasional
 harmful 'failed to decode ...' errors from runc run or exec.
* Fixed the check in cgroup v1 systemd manager if a container needs to be
 frozen before Set, and add a setting to skip such freeze unconditionally.
 The previous fix for that issue, done in runc 1.0.1, was not working.

Update to runc v1.0.1. Upstream changelog is available from

[link moved to references]

* Fixed occasional runc exec/run failure ('interrupted system call') on an
 Azure volume.
* Fixed 'unable to find groups ... token too long' error with /etc/group
 containing lines longer than 64K characters.
* cgroup/systemd/v1: fix leaving cgroup frozen after Set if a parent cgroup is
 frozen. This is a regression in 1.0.0, not affecting runc itself but some
 of libcontainer users (e.g Kubernetes).
* cgroupv2: bpf: Ignore inaccessible existing programs in case of
 permission error when handling replacement of existing bpf cgroup
 programs. This fixes a regression in 1.0.0, where some SELinux
 policies would block runc from being able to run entirely.
* cgroup/systemd/v2: don't freeze cgroup on Set.
* cgroup/systemd/v1: avoid unnecessary freeze on Set.
- fix issues with runc under openSUSE MicroOS's SELinux policy. bsc#1187704

Update to runc v1.0.0. Upstream changelog is available from

[link moved to references]

! The usage of relative paths for mountpoints will now produce a warning
 (such configurations are outside of the spec, and in future runc will
 produce an error when given such configurations).
* cgroupv2: devices: rework the filter generation to produce consistent
 results with cgroupv1, and always clobber any existing eBPF
 program(s) to fix runc update and avoid leaking eBPF programs
 (resulting in errors when managing containers).
* cgroupv2: correctly convert 'number of IOs' statistics in a
 cgroupv1-compatible way.
* cgroupv2: support larger than 32-bit IO statistics on 32-bit ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'containerd, docker, runc' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.4.11~56.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.9_ce~156.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.9_ce~156.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.9_ce~156.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.0.2~23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo", rpm:"runc-debuginfo~1.0.2~23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.4.11~56.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.9_ce~156.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.9_ce~156.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~20.10.9_ce~156.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~20.10.9_ce~156.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.0.2~23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc-debuginfo", rpm:"runc-debuginfo~1.0.2~23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.4.11~56.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.9_ce~156.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.9_ce~156.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.0.2~23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.4.11~56.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.9_ce~156.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~20.10.9_ce~156.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.0.2~23.1", rls:"SLES15.0SP1"))) {
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
