# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14659.1");
  script_cve_id("CVE-2017-9763", "CVE-2020-14372", "CVE-2020-25632", "CVE-2020-25647", "CVE-2020-27749", "CVE-2020-27779", "CVE-2021-20225", "CVE-2021-20233");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:42 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-10 20:28:25 +0000 (Wed, 10 Mar 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14659-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14659-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114659-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182263");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2021-March/018162.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the SUSE-SU-2021:14659-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grub2 fixes the following issues:

grub2 now implements the new 'SBAT' method for SHIM based secure boot revocation. (bsc#1182057)

grub2 was updated to the 2.02 version (same as SUSE Linux Enterprise 12 SP3).

Following security issues are fixed that can violate secure boot constraints:

- CVE-2020-25632: Fixed a use-after-free in rmmod command (bsc#1176711)
- CVE-2020-25647: Fixed an out-of-bound write in grub_usb_device_initialize() (bsc#1177883)
- CVE-2020-27749: Fixed a stack buffer overflow in grub_parser_split_cmdline (bsc#1179264)
- CVE-2020-27779, CVE-2020-14372: Disallow cutmem and acpi commands in secure boot mode (bsc#1179265 bsc#1175970)
- CVE-2021-20225: Fixed a heap out-of-bounds write in short form option parser (bsc#1182262)
- CVE-2021-20233: Fixed a heap out-of-bound write due to mis-calculation of space required for quoting (bsc#1182263)");

  script_tag(name:"affected", value:"'grub2' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-efi", rpm:"grub2-x86_64-efi~2.02~0.66.26.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-xen", rpm:"grub2-x86_64-xen~2.02~0.66.26.1", rls:"SLES11.0SP4"))) {
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
