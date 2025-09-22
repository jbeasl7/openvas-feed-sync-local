# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833822");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-13754", "CVE-2021-3638", "CVE-2021-3750", "CVE-2021-3929", "CVE-2022-1050", "CVE-2022-26354", "CVE-2023-0330", "CVE-2023-2861", "CVE-2023-3180", "CVE-2023-3354");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 12:26:12 +0000 (Fri, 08 Apr 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:37:49 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for qemu (SUSE-SU-2023:3721-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3721-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EKKYKNR7L2UDHHJGX2LBOORZBXYAMFBX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the SUSE-SU-2023:3721-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

  * CVE-2022-26354: Fixed a memory leak due to a missing virtqueue detach on
      error. (bsc#1198712)

  * CVE-2021-3929: Fixed an use-after-free in nvme DMA reentrancy issue.
      (bsc#1193880)

  * CVE-2023-0330: Fixed a stack overflow due to a DMA reentrancy issue.
      (bsc#1207205)

  * CVE-2020-13754: Fixed a DoS due to an OOB access during mmio operations.
      (bsc#1172382)

  * CVE-2023-3354: Fixed a remote unauthenticated DoS due to an improper I/O
      watch removal in VNC TLS handshake. (bsc#1212850)

  * CVE-2023-3180: Fixed a heap buffer overflow in
      virtio_crypto_sym_op_helper(). (bsc#1213925)

  * CVE-2021-3638: Fixed an out-of-bounds write due to an inconsistent check in
      ati_2d_blt(). (bsc#1188609)

  * CVE-2021-3750: Fixed an use-after-free in DMA reentrancy issue.
      (bsc#1190011)

  * CVE-2023-2861: Fixed improper access control on special files in 9pfs
      (bsc#1212968).

  * CVE-2022-1050: Fixed use-after-free issue in pvrdma_exec_cmd()
      (bsc#1197653).

  The following non-security bug was fixed:

  * Prepare for binutils update to 2.41 update (bsc#1215311).

  ##");

  script_tag(name:"affected", value:"'qemu' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~4.2.1~150200.79.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~4.2.1~150200.79.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~4.2.1~150200.79.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~4.2.1~150200.79.1", rls:"openSUSELeap15.4"))) {
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