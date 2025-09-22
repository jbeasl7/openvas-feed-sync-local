# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1497.1");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1497-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1497-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241497-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219563");
  script_xref(name:"URL", value:"https://github.com/containers/image/pull/1944");
  script_xref(name:"URL", value:"https://github.com/containers/image/pull/2070");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035145.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'skopeo' package(s) announced via the SUSE-SU-2024:1497-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for skopeo fixes the following issues:

- Update to version 1.14.2:
 * [release-1.14] Bump Skopeo to v1.14.2
 * [release-1.14] Bump c/image to v5.29.2, c/common to v0.57.3 (fixes bsc#1219563)

- Update to version 1.14.1:
 * Bump to v1.14.1
 * fix(deps): update module github.com/containers/common to v0.57.2
 * fix(deps): update module github.com/containers/image/v5 to v5.29.1
 * chore(deps): update dependency containers/automation_images to v20240102
 * Fix libsubid detection
 * fix(deps): update module golang.org/x/term to v0.16.0
 * fix(deps): update golang.org/x/exp digest to 02704c9
 * chore(deps): update dependency containers/automation_images to v20231208
 * [skip-ci] Update actions/stale action to v9
 * fix(deps): update module github.com/containers/common to v0.57.1
 * fix(deps): update golang.org/x/exp digest to 6522937
 * DOCS: add Gentoo in install.md
 * DOCS: Update to add Arch Linux in install.md
 * fix(deps): update module golang.org/x/term to v0.15.0
 * Bump to v1.14.1-dev

- Update to version 1.14.0:
 * Bump to v1.14.0
 * fix(deps): update module github.com/containers/common to v0.57.0
 * chore(deps): update dependency containers/automation_images to v20231116
 * fix(deps): update module github.com/containers/image/v5 to v5.29.0
 * Add documentation and smoke tests for the new --compat-auth-file options
 * Update c/image and c/common to latest
 * fix(deps): update module github.com/containers/storage to v1.51.0
 * fix(deps): update module golang.org/x/term to v0.14.0
 * fix(deps): update module github.com/spf13/cobra to v1.8.0
 * [CI:DOCS] Update dependency golangci/golangci-lint to v1.55.2
 * [CI:DOCS] Update dependency golangci/golangci-lint to v1.55.1
 * fix(deps): update github.com/containers/common digest to 3e5caa0
 * chore(deps): update module google.golang.org/grpc to v1.57.1 [security]
 * fix(deps): update module github.com/containers/ocicrypt to v1.1.9
 * Update github.com/klauspost/compress to v1.17.2
 * chore(deps): update module github.com/docker/docker to v24.0.7+incompatible [security]
 * Fix ENTRYPOINT documentation, drop others.
 * Remove unused environment variables in Cirrus
 * [CI:DOCS] Update dependency golangci/golangci-lint to v1.55.0
 * chore(deps): update dependency containers/automation_images to v20231004
 * chore(deps): update module golang.org/x/net to v0.17.0 [security]
 * copy: Note support for `zstd:chunked`
 * fix(deps): update module golang.org/x/term to v0.13.0
 * fix(deps): update module github.com/docker/distribution to v2.8.3+incompatible
 * fix(deps): update github.com/containers/common digest to 745eaa4
 * Packit: switch to @containers/packit-build team for copr failure notification comments
 * Packit: tag @lsm5 on copr build failures
 * vendor of containers/common
 * fix(deps): update module github.com/opencontainers/image-spec to v1.1.0-rc5
 * fix(deps): update module github.com/containers/common to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'skopeo' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~1.14.2~150300.11.8.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~1.14.2~150300.11.8.1", rls:"SLES15.0SP4"))) {
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
