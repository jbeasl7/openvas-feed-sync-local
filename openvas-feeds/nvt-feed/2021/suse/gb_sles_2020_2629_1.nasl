# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2629.1");
  script_cve_id("CVE-2020-10713");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:54 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-05 14:33:27 +0000 (Wed, 05 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2629-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2629-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202629-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shim' package(s) announced via the SUSE-SU-2020:2629-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for shim fixes the following issues:

This update addresses the 'BootHole' security issue (master CVE CVE-2020-10713), by disallowing binaries signed by the previous SUSE UEFI signing key from booting.

This update should only be installed after updates of grub2, the Linux kernel and (if used) Xen from July / August 2020 are applied.


Changes:

Use vendor-dbx to block old SUSE/openSUSE signkeys (bsc#1168994)

Add dbx-cert.tar.xz which contains the certificates to block and a
 script, generate-vendor-dbx.sh, to generate vendor-dbx.bin

Add vendor-dbx.bin as the vendor dbx to block unwanted keys


Update the path to grub-tpm.efi in shim-install (bsc#1174320)

Only check EFI variable copying when Secure Boot is enabled (bsc#1173411)

Use the full path of efibootmgr to avoid errors when invoking
 shim-install from packagekitd (bsc#1168104)

shim-install: add check for btrfs is used as root file system to enable
 relative path lookup for file. (bsc#1153953)

shim-install: install MokManager to \EFI\boot to process the pending MOK
 request (bsc#1175626, bsc#1175656)");

  script_tag(name:"affected", value:"'shim' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"shim", rpm:"shim~15+git47~3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shim-debuginfo", rpm:"shim-debuginfo~15+git47~3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shim-debugsource", rpm:"shim-debugsource~15+git47~3.8.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"shim", rpm:"shim~15+git47~3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shim-debuginfo", rpm:"shim-debuginfo~15+git47~3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shim-debugsource", rpm:"shim-debugsource~15+git47~3.8.1", rls:"SLES15.0SP2"))) {
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
