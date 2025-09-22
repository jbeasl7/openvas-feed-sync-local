# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2946.1");
  script_cve_id("CVE-2016-6834", "CVE-2016-6835", "CVE-2016-9602", "CVE-2016-9603", "CVE-2017-10664", "CVE-2017-10806", "CVE-2017-10911", "CVE-2017-11334", "CVE-2017-11434", "CVE-2017-12809", "CVE-2017-13672", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15289", "CVE-2017-5579", "CVE-2017-5973", "CVE-2017-5987", "CVE-2017-6505", "CVE-2017-7377", "CVE-2017-7471", "CVE-2017-7493", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8112", "CVE-2017-8309", "CVE-2017-8379", "CVE-2017-8380", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9375", "CVE-2017-9503");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 14:29:43 +0000 (Thu, 06 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2946-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2946-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172946-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994605");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-November/003378.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2017:2946-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes several issues.

These security issues were fixed:

- CVE-2017-10911: The make_response function in the Linux kernel allowed guest OS users to obtain sensitive information from host OS (or other guest OS) kernel memory by leveraging the copying of uninitialized padding fields in Xen block-interface response structures (bsc#1057378).
- CVE-2017-12809: The IDE disk and CD/DVD-ROM Emulator support allowed local guest OS privileged users to cause a denial of service (NULL pointer dereference and QEMU process crash) by flushing an empty CDROM device drive (bsc#1054724).
- CVE-2017-15289: The mode4and5 write functions allowed local OS guest privileged users to cause a denial of service (out-of-bounds write access and Qemu process crash) via vectors related to dst calculation (bsc#1063122)
- CVE-2017-15038: Race condition in the v9fs_xattrwalk function local guest OS users to obtain sensitive information from host heap memory via vectors related to reading extended attributes (bsc#1062069)
- CVE-2017-14167: Integer overflow in the load_multiboot function allowed local guest OS users to execute arbitrary code on the host via crafted multiboot header address values, which trigger an out-of-bounds write (bsc#1057585)
- CVE-2017-11434: The dhcp_decode function in slirp/bootp.c allowed local guest OS users to cause a denial of service (out-of-bounds read) via a crafted DHCP options string (bsc#1049381)
- CVE-2017-11334: The address_space_write_continue function allowed local guest OS privileged users to cause a denial of service (out-of-bounds access and guest instance crash) by leveraging use of qemu_map_ram_ptr to access guest ram block area (bsc#1048902)
- CVE-2017-13672: The VGA display emulator support allowed local guest OS privileged users to cause a denial of service (out-of-bounds read and QEMU process crash) via vectors involving display update (bsc#1056334)
- CVE-2017-5973: A infinite loop while doing control transfer in xhci_kick_epctx allowed privileged user inside the guest to crash the host process resulting in DoS (bsc#1025109)
- CVE-2017-5987: The sdhci_sdma_transfer_multi_blocks function in hw/sd/sdhci.c allowed local OS guest privileged users to cause a denial of service (infinite loop and QEMU process crash) via vectors involving the transfer mode register during multi block transfer (bsc#1025311)
- CVE-2017-6505: The ohci_service_ed_list function allowed local guest OS users to cause a denial of service (infinite loop) via vectors involving the number of link endpoint list descriptors (bsc#1028184)
- CVE-2016-9603: A privileged user within the guest VM could have caused a heap overflow in the device model process, potentially escalating their privileges to that of the device model process (bsc#1028656)
- CVE-2017-7718: hw/display/cirrus_vga_rop.h allowed local guest OS privileged users to cause a denial of service (out-of-bounds read ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.3.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.3.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.3.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.3.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.3.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.3.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.3.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.3.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.8.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.3.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.8.1~33.3.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.3.1~33.3.3", rls:"SLES12.0SP1"))) {
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
