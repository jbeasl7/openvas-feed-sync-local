# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856342");
  script_cve_id("CVE-2023-30549", "CVE-2023-38496", "CVE-2024-3727");
  script_tag(name:"creation_date", value:"2024-08-17 04:00:25 +0000 (Sat, 17 Aug 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-14 15:42:07 +0000 (Tue, 14 May 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0244-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0244-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3BEJQC6TDQZLJ4YE746IHLCFJFUQ2JKQ/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224114");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apptainer' package(s) announced via the openSUSE-SU-2024:0244-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apptainer fixes the following issues:

- Make sure, digest values handled by the Go library
 github.com/opencontainers/go-digest and used throughout the
 Go-implemented containers ecosystem are always validated. This
 prevents attackers from triggering unexpected authenticated
 registry accesses. (CVE-2024-3727, boo#1224114).


- Updated apptainer to version 1.3.0
 * FUSE mounts are now supported in setuid mode, enabling full
 functionality even when kernel filesystem mounts are insecure due to
 unprivileged users having write access to raw filesystems in
 containers. When allow `setuid-mount extfs = no` (the default) in
 apptainer.conf, then the fuse2fs image driver will be used to mount
 ext3 images in setuid mode instead of the kernel driver (ext3 images
 are primarily used for the `--overlay` feature), restoring
 functionality that was removed by default in Apptainer 1.1.8 because
 of the security risk.
 The allow `setuid-mount squashfs` configuration option in
 `apptainer.conf` now has a new default called `iflimited` which allows
 kernel squashfs mounts only if there is at least one `limit container`
 option set or if Execution Control Lists are activated in ecl.toml.
 If kernel squashfs mounts are are not allowed, then the squashfuse
 image driver will be used instead.
 `iflimited` is the default because if one of those limits are used
 the system administrator ensures that unprivileged users do not have
 write access to the containers, but on the other hand using FUSE
 would enable a user to theoretically bypass the limits via `ptrace()`
 because the FUSE process runs as that user.
 The `fuse-overlayfs` image driver will also now be tried in setuid
 mode if the kernel overlayfs driver does not work (for example if
 one of the layers is a FUSE filesystem). In addition, if `allow
 setuid-mount encrypted = no` then the unprivileged gocryptfs format
 will be used for encrypting SIF files instead of the kernel
 device-mapper. If a SIF file was encrypted using the gocryptfs
 format, it can now be mounted in setuid mode in addition to
 non-setuid mode.
 * Change the default in user namespace mode to use either kernel
 overlayfs or fuse-overlayfs instead of the underlay feature for the
 purpose of adding bind mount points. That was already the default in
 setuid mode, this change makes it consistent. The underlay feature
 can still be used with the `--underlay` option, but it is deprecated
 because the implementation is complicated and measurements have
 shown that the performance of underlay is similar to overlayfs and
 fuse-overlayfs.
 For now the underlay feature can be made the default again with a
 new `preferred` value on the `enable underlay` configuration option.
 Also the `--underlay` option can be used in setuid mode or as the
 root user, although it was ignored previously.
 * Prefer again to use kernel overlayfs over fuse-overlayfs when a
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'apptainer' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"apptainer", rpm:"apptainer~1.3.0~bp155.3.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-leap", rpm:"apptainer-leap~1.3.0~bp155.3.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-sle15_5", rpm:"apptainer-sle15_5~1.3.0~bp155.3.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-sle15_6", rpm:"apptainer-sle15_6~1.3.0~bp155.3.3.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsquashfuse0", rpm:"libsquashfuse0~0.5.0~bp155.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse", rpm:"squashfuse~0.5.0~bp155.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse-devel", rpm:"squashfuse-devel~0.5.0~bp155.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfuse-tools", rpm:"squashfuse-tools~0.5.0~bp155.2.1", rls:"openSUSELeap15.5"))) {
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
