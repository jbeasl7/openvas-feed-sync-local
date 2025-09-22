# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0857.1");
  script_cve_id("CVE-2024-22038");
  script_tag(name:"creation_date", value:"2025-03-17 15:24:00 +0000 (Mon, 17 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0857-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0857-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250857-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230469");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020511.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'build' package(s) announced via the SUSE-SU-2025:0857-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for build fixes the following issues:
- CVE-2024-22038: Fixed DoS attacks, information leaks with crafted Git repositories (bnc#1230469)

Other fixes:
- Fixed behaviour when using '--shell' aka 'osc shell' option
 in a VM build. Startup is faster and permissions stay intact
 now.

- fixes for POSIX compatibility for obs-docker-support adn
 mkbaselibs
- Add support for apk in docker/podman builds
- Add support for 'wget' in Docker images
- Fix debian support for Dockerfile builds
- Fix preinstallimages in containers
- mkosi: add back system-packages used by build-recipe directly
- pbuild: parse the Release files for debian repos

- mkosi: drop most systemd/build-packages deps and use obs_scm
 directory as source if present
- improve source copy handling
- Introduce --repos-directory and --containers-directory options

- productcompose: support of building against a baseiso
- preinstallimage: avoid inclusion of build script generated files
- preserve timestamps on sources copy-in for kiwi and productcompose
- alpine package support updates
- tumbleweed config update

- debian: Support installation of foreign architecture packages
 (required for armv7l setups)
- Parse unknown timezones as UTC
- Apk (Alpine Linux) format support added
- Implement default value in parameter expansion
- Also support supplements that use & as 'and'
- Add workaround for skopeo's argument parser
- add cap-htm=off on power9
- Fixed usage of chown calls
- Remove leading `go` from `purl` locators

- container related:
 * Implement support for the new <containers> element in kiwi recipes
 * Fixes for SBOM and dependencies of multi stage container builds
 * obs-docker-support: enable dnf and yum substitutions
- Arch Linux:
 * fix file path for Arch repo
 * exclude unsupported arch
 * Use root as download user
- build-vm-qemu: force sv48 satp mode on riscv64
- mkosi:
 * Create .sha256 files after mkosi builds
 * Always pass --image-version to mkosi
- General improvements and bugfixes (mkosi, pbuild, appimage/livebuild,
 obs work detection, documention, SBOM)
- Support slsa v1 in unpack_slsa_provenance
- generate_sbom: do not clobber spdx supplier
- Harden export_debian_orig_from_git (bsc#1230469)

- SBOM generation:
 - Adding golang introspection support
 - Adding rust binary introspection support
 - Keep track of unknwon licenses and add a 'hasExtractedLicensingInfos'
 section
 - Also normalize licenses for cyclonedx
 - Make generate_sbom errors fatal
 - general improvements
- Fix noprep building not working because the buildir is removed
- kiwi image: also detect a debian build if /var/lib/dpkg/status is present
- Do not use the Encode module to convert a code point to utf8
- Fix personality syscall number for riscv
- add more required recommendations for KVM builds
- set PACKAGER field in build-recipe-arch
- fix writing _modulemd.yaml
- pbuild: support --release and --baselibs option
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'build' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"build", rpm:"build~20250306~150200.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"build-initvm-aarch64", rpm:"build-initvm-aarch64~20250306~150200.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"build-initvm-powerpc64le", rpm:"build-initvm-powerpc64le~20250306~150200.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"build-initvm-s390x", rpm:"build-initvm-s390x~20250306~150200.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"build-initvm-x86_64", rpm:"build-initvm-x86_64~20250306~150200.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"build-mkbaselibs", rpm:"build-mkbaselibs~20250306~150200.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"build-mkdrpms", rpm:"build-mkdrpms~20250306~150200.19.1", rls:"openSUSELeap15.6"))) {
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
