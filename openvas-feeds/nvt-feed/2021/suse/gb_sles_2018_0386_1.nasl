# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0386.1");
  script_cve_id("CVE-2017-14992", "CVE-2017-16539");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-27 15:55:07 +0000 (Mon, 27 Nov 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0386-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0386-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180386-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Version update for docker, containerd, docker-runc, golang-github-docker-libnetwork' package(s) announced via the SUSE-SU-2018:0386-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker, docker-runc, containerd,
golang-github-docker-libnetwork fixes several issues.
These security issues were fixed:
- CVE-2017-16539: The DefaultLinuxSpec function in oci/defaults.go docker
 did not block /proc/scsi pathnames, which allowed attackers to trigger
 data loss (when certain older Linux kernels are used) by leveraging
 Docker container access to write a 'scsi remove-single-device' line to
 /proc/scsi/scsi, aka SCSI MICDROP (bnc#1066801)
- CVE-2017-14992: Lack of content verification in docker allowed a remote
 attacker to cause a Denial of Service via a crafted image layer payload,
 aka gzip bombing. (bnc#1066210)
These non-security issues were fixed:
- bsc#1059011: The systemd service helper script used a timeout of 60
 seconds to start the daemon, which is insufficient in cases where the
 daemon takes longer to start. Instead, set the service type from
 'simple' to 'notify' and remove the now superfluous helper script.
- bsc#1057743: New requirement with new version of docker-libnetwork.
- bsc#1032287: Missing docker systemd configuration.
- bsc#1057743: New 'symbol' for libnetwork requirement.
- bsc#1057743: Update secrets patch to handle 'old' containers that have
 orphaned secret data no longer available on the host.
- bsc#1055676: Update patches to correctly handle volumes and mounts when
 Docker is running with user namespaces enabled.
- bsc#1045628:: Add patch to make the dm storage driver remove a
 container's rootfs mountpoint before attempting to do libdm operations
 on it. This helps avoid complications when live mounts will leak into
 containers.
- bsc#1069758: Upgrade Docker to v17.09.1_ce (and obsolete
 docker-image-migrator).
- bsc#1021227: bsc#1029320 bsc#1058173 -- Enable docker devicemapper
 support for deferred removal/deletion within Containers module.
- bsc#1046024: Correct interaction between Docker and SuSEFirewall2, to
 avoid breaking Docker networking after boot.
- bsc#1048046: Build with -buildmode=pie to make all binaries PIC.
- bsc#1072798: Remove dependency on obsolete bridge-utils.
- bsc#1064926: Set --start-timeout=2m by default to match upstream.
- bsc#1065109, bsc#1053532: Use the upstream makefile so that Docker can
 get the commit ID in `docker info`.
Please note that the 'docker-runc' package is just a rename of the old
'runc' package to match that we now ship the Docker fork of runc.");

  script_tag(name:"affected", value:"'Version update for docker, containerd, docker-runc, golang-github-docker-libnetwork' package(s) on SUSE Linux Enterprise Module for Containers 12, SUSE OpenStack Cloud 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~0.2.9+gitr706_06b9cb351610~16.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-debuginfo", rpm:"containerd-debuginfo~0.2.9+gitr706_06b9cb351610~16.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-debugsource", rpm:"containerd-debugsource~0.2.9+gitr706_06b9cb351610~16.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~17.09.1_ce~98.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~17.09.1_ce~98.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~17.09.1_ce~98.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2066_7b2b1feb1de4~10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2066_7b2b1feb1de4~10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc4+gitr3338_3f2f8b84a77f~1.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-docker-libnetwork-debugsource", rpm:"golang-github-docker-libnetwork-debugsource~0.7.0.1+gitr2066_7b2b1feb1de4~10.1", rls:"SLES12.0"))) {
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
