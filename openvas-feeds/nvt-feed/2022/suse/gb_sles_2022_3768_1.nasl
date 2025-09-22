# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3768.1");
  script_cve_id("CVE-2020-17380", "CVE-2020-25085", "CVE-2021-3409", "CVE-2021-3507", "CVE-2021-4206", "CVE-2021-4207", "CVE-2022-0216", "CVE-2022-35414");
  script_tag(name:"creation_date", value:"2022-10-27 04:38:58 +0000 (Thu, 27 Oct 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-18 14:08:55 +0000 (Mon, 18 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3768-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3768-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223768-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201367");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-October/012710.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2022:3768-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

- CVE-2021-3409: Fixed an incomplete fix for CVE-2020-17380 and CVE-2020-25085 in sdhi controller. (bsc#1182282)
- CVE-2021-4206: Fixed an integer overflow in cursor_alloc which can lead to heap buffer overflow. (bsc#1198035)
- CVE-2021-4207: Fixed a double fetch in qxl_cursor ehich can lead to heap buffer overflow. (bsc#1198037)
- CVE-2022-0216: Fixed a use after free issue found in hw/scsi/lsi53c895a.c. (bsc#1198038)
- CVE-2022-35414: Fixed an uninitialized read during address translation that leads to a crash. (bsc#1201367)
- CVE-2021-3507: Fixed a heap buffer overflow in DMA read data transfers. (bsc#1185000)
- CVE-2020-17380: Fixed a heap buffer overflow in sdhci_sdma_transfer_multi_blocks. (bsc#1175144)");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa", rpm:"qemu-audio-alsa~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss", rpm:"qemu-audio-oss~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa", rpm:"qemu-audio-pa~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0+~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.12.0_0_ga698c89~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses", rpm:"qemu-ui-curses~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk", rpm:"qemu-ui-gtk~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.12.0_0_ga698c89~150100.80.43.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~3.1.1.1~150100.80.43.2", rls:"SLES15.0SP1"))) {
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
