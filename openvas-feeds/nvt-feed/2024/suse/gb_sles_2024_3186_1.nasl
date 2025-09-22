# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3186.1");
  script_cve_id("CVE-2024-1753", "CVE-2024-24786", "CVE-2024-28180", "CVE-2024-3727");
  script_tag(name:"creation_date", value:"2024-09-10 13:04:13 +0000 (Tue, 10 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 15:15:41 +0000 (Mon, 18 Mar 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3186-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3186-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243186-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224117");
  script_xref(name:"URL", value:"https://github.com/containers/common/pull/1846");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-September/019398.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah' package(s) announced via the SUSE-SU-2024:3186-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah fixes the following issues:

Update to version 1.35.4:

* CVE-2024-3727 updates (bsc#1224117)
* Bump go-jose CVE-2024-28180
* Bump ocicrypt and go-jose CVE-2024-28180

Update to version 1.35.3:

* correctly configure /etc/hosts and resolv.conf
* buildah: refactor resolv/hosts setup.
* rename the hostFile var to reflect
* CVE-2024-24786 protobuf to 1.33


Update to version 1.35.1:

* CVE-2024-1753 container escape fix (bsc#1221677)

- Buildah dropped cni support, require netavark instead (bsc#1221243)

- Remove obsolete requires libcontainers-image & libcontainers-storage

- Require passt for rootless networking (poo#156955)
 Buildah moved to passt/pasta for rootless networking from slirp4netns
 ([link moved to references])

Update to version 1.35.0:

* Bump c/common v0.58.0, c/image v5.30.0, c/storage v1.53.0
* conformance tests: don't break on trailing zeroes in layer blobs
* Add a conformance test for copying to a mounted prior stage
* cgroups: reuse version check from c/common
* Update vendor of containers/(common,image)
* manifest add: complain if we get artifact flags without --artifact
* Use retry logic from containers/common
* Vendor in containers/(storage,image,common)
* Update module golang.org/x/crypto to v0.20.0
* Add comment re: Total Success task name
* tests: skip_if_no_unshare(): check for --setuid
* Properly handle build --pull=false
* Update module go.etcd.io/bbolt to v1.3.9
* Update module github.com/opencontainers/image-spec to v1.1.0
* build --all-platforms: skip some base 'image' platforms
* Bump main to v1.35.0-dev
* Vendor in latest containers/(storage,image,common)
* Split up error messages for missing --sbom related flags
* `buildah manifest`: add artifact-related options
* cmd/buildah/manifest.go: lock lists before adding/annotating/pushing
* cmd/buildah/manifest.go: don't make struct declarations aliases
* Use golang.org/x/exp/slices.Contains
* Try Cirrus with a newer VM version
* Set CONTAINERS_CONF in the chroot-mount-flags integration test
* Update to match dependency API update
* Update github.com/openshift/imagebuilder and containers/common
* docs: correct default authfile path
* tests: retrofit test for heredoc summary
* build, heredoc: show heredoc summary in build output
* manifest, push: add support for --retry and --retry-delay
* imagebuildah: fix crash with empty RUN
* Make buildah match podman for handling of ulimits
* docs: move footnotes to where they're applicable
* Allow users to specify no-dereference
* docs: use reversed logo for dark theme in README
* build,commit: add --sbom to scan and produce SBOMs when committing
* commit: force omitHistory if the parent has layers but no history
* docs: fix a couple of typos
* internal/mkcw.Archive(): handle extra image content
* stage_executor,heredoc: honor interpreter in heredoc
* stage_executor,layers: burst cache if heredoc content is changed
* Replace ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'buildah' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.35.4~150400.3.30.1", rls:"SLES15.0SP4"))) {
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
