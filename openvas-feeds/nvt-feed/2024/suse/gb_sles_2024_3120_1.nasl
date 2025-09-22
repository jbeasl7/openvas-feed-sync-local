# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3120.1");
  script_cve_id("CVE-2024-1753", "CVE-2024-23651", "CVE-2024-23652", "CVE-2024-23653", "CVE-2024-24786", "CVE-2024-28180", "CVE-2024-3727", "CVE-2024-41110");
  script_tag(name:"creation_date", value:"2024-09-04 04:26:54 +0000 (Wed, 04 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 01:44:46 +0000 (Fri, 09 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3120-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3120-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243120-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228324");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/25.0/#2506");
  script_xref(name:"URL", value:"https://github.com/containers/common/pull/1846");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036751.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah, docker' package(s) announced via the SUSE-SU-2024:3120-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah, docker fixes the following issues:

Changes in docker:
- CVE-2024-23651: Fixed arbitrary files write due to race condition on mounts (bsc#1219267)
- CVE-2024-23652: Fixed insufficient validation of parent directory on mount (bsc#1219268)
- CVE-2024-23653: Fixed insufficient validation on entitlement on container creation via buildkit (bsc#1219438)
- CVE-2024-41110: A Authz zero length regression that could lead to authentication bypass was fixed (bsc#1228324)

Other fixes:

- Update to Docker 25.0.6-ce. See upstream changelog online at
 <[link moved to references]>
- Update to Docker 25.0.5-ce (bsc#1223409)

- Fix BuildKit's symlink resolution logic to correctly handle non-lexical
 symlinks. (bsc#1221916)
- Write volume options atomically so sudden system crashes won't result in
 future Docker starts failing due to empty files. (bsc#1214855)

Changes in buildah:
- Update to version 1.35.4:
 * [release-1.35] Bump to Buildah v1.35.4
 * [release-1.35] CVE-2024-3727 updates (bsc#1224117)
 * integration test: handle new labels in 'bud and test --unsetlabel'
 * [release-1.35] Bump go-jose CVE-2024-28180
 * [release-1.35] Bump ocicrypt and go-jose CVE-2024-28180

- Update to version 1.35.3:
 * [release-1.35] Bump to Buildah v1.35.3
 * [release-1.35] correctly configure /etc/hosts and resolv.conf
 * [release-1.35] buildah: refactor resolv/hosts setup.
 * [release-1.35] rename the hostFile var to reflect
 * [release-1.35] Bump c/common to v0.58.1
 * [release-1.35] Bump Buildah to v1.35.2
 * [release-1.35] CVE-2024-24786 protobuf to 1.33
 * [release-1.35] Bump to v1.35.2-dev

- Update to version 1.35.1:
 * [release-1.35] Bump to v1.35.1
 * [release-1.35] CVE-2024-1753 container escape fix (bsc#1221677)

- Buildah dropped cni support, require netavark instead (bsc#1221243)

- Remove obsolete requires libcontainers-image & libcontainers-storage

- Require passt for rootless networking (poo#156955)
 Buildah moved to passt/pasta for rootless networking from slirp4netns
 ([link moved to references])

- Update to version 1.35.0:
 * Bump v1.35.0
 * Bump c/common v0.58.0, c/image v5.30.0, c/storage v1.53.0
 * conformance tests: don't break on trailing zeroes in layer blobs
 * Add a conformance test for copying to a mounted prior stage
 * fix(deps): update module github.com/stretchr/testify to v1.9.0
 * cgroups: reuse version check from c/common
 * Update vendor of containers/(common,image)
 * fix(deps): update github.com/containers/storage digest to eadc620
 * fix(deps): update github.com/containers/luksy digest to ceb12d4
 * fix(deps): update github.com/containers/image/v5 digest to cdc6802
 * manifest add: complain if we get artifact flags without --artifact
 * Use retry logic from containers/common
 * Vendor in containers/(storage,image,common)
 * Update module golang.org/x/crypto to v0.20.0
 * Add comment re: Total Success task name
 * tests: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'buildah, docker' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~25.0.6_ce~150000.207.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~25.0.6_ce~150000.207.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.35.4~150300.8.25.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~25.0.6_ce~150000.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~25.0.6_ce~150000.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~25.0.6_ce~150000.207.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~25.0.6_ce~150000.207.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~25.0.6_ce~150000.207.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-rootless-extras", rpm:"docker-rootless-extras~25.0.6_ce~150000.207.1", rls:"SLES15.0SP4"))) {
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
