# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833794");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2015-4645", "CVE-2015-4646", "CVE-2021-40153", "CVE-2021-41072");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-24 18:39:50 +0000 (Fri, 24 Sep 2021)");
  script_tag(name:"creation_date", value:"2024-03-04 07:31:43 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for squashfs (SUSE-SU-2023:4591-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeap15\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4591-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KWSH3QGL2D7HNLD3ELENEP5JABWEH4SR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squashfs'
  package(s) announced via the SUSE-SU-2023:4591-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squashfs fixes the following issues:

  * CVE-2015-4645, CVE-2015-4646: Multiple buffer overflows fixed in squashfs-
      tools (bsc#935380)

  * CVE-2021-40153: Fixed an issue where an attacker might have been able to
      write a file outside of destination (bsc#1189936)

  * CVE-2021-41072: Fixed an issue where an attacker might have been able to
      write a file outside the destination directory via a symlink (bsc#1190531).

  update to 4.6.1:

  * Race condition which can cause corruption of the 'fragment table' fixed.
      This is a regression introduced in August 2022, and it has been seen when
      tailend packing is used (-tailends option).

  * Fix build failure when the tools are being built without extended attribute
      (XATTRs) support.

  * Fix XATTR error message when an unrecognised prefix is found

  * Fix incorrect free of pointer when an unrecognised XATTR prefix is found.

  * Major improvements in extended attribute handling, pseudo file handling, and
      miscellaneous new options and improvements

  * Extended attribute handling improved in Mksquashfs and Sqfstar

  * New Pseudo file xattr definition to add extended attributes to files.

  * New xattrs-add Action to add extended attributes to files

  * Extended attribute handling improved in Unsquashfs

  * Other major improvements

  * Unsquashfs can now output Pseudo files to standard out.

  * Mksquashfs can now input Pseudo files from standard in.

  * Squashfs filesystems can now be converted (different block size compression
      etc) without unpacking to an intermediate filesystem or mounting, by piping
      the output of Unsquashfs to Mksquashfs.

  * Pseudo files are now supported by Sqfstar.

  * 'Non-anchored' excludes are now supported by Unsquashfs.

  update to 4.5.1 (bsc#1190531, CVE-2021-41072):

  * This release adds Manpages for Mksquashfs(1), Unsquashfs(1), Sqfstar(1) and
      Sqfscat(1).

  * The -help text output from the utilities has been improved and extended as
      well (but the Manpages are now more comprehensive).

  * CVE-2021-41072 which is a writing outside of destination exploit, has been
      fixed.

  * The number of hard-links in the filesystem is now also displayed by
      Mksquashfs in the output summary.

  * The number of hard-links written by Unsquashfs is now also displayed in the
      output summary.

  * Unsquashfs will now write to a pre-existing destination directory, rather
      than aborting.

  * Unsquashfs now a ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'squashfs' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debuginfo", rpm:"squashfs-debuginfo~4.6.1~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debugsource", rpm:"squashfs-debugsource~4.6.1~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs", rpm:"squashfs~4.6.1~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debuginfo", rpm:"squashfs-debuginfo~4.6.1~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debugsource", rpm:"squashfs-debugsource~4.6.1~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs", rpm:"squashfs~4.6.1~150300.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debuginfo", rpm:"squashfs-debuginfo~4.6.1~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debugsource", rpm:"squashfs-debugsource~4.6.1~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs", rpm:"squashfs~4.6.1~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debuginfo", rpm:"squashfs-debuginfo~4.6.1~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debugsource", rpm:"squashfs-debugsource~4.6.1~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs", rpm:"squashfs~4.6.1~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debuginfo", rpm:"squashfs-debuginfo~4.6.1~150300.3.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debugsource", rpm:"squashfs-debugsource~4.6.1~150300.3.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs", rpm:"squashfs~4.6.1~150300.3.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debuginfo", rpm:"squashfs-debuginfo~4.6.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debugsource", rpm:"squashfs-debugsource~4.6.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs", rpm:"squashfs~4.6.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debuginfo", rpm:"squashfs-debuginfo~4.6.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debugsource", rpm:"squashfs-debugsource~4.6.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs", rpm:"squashfs~4.6.1~150300.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debuginfo", rpm:"squashfs-debuginfo~4.6.1~150300.3.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs-debugsource", rpm:"squashfs-debugsource~4.6.1~150300.3.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squashfs", rpm:"squashfs~4.6.1~150300.3.3.1##", rls:"openSUSELeapMicro5.4"))) {
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