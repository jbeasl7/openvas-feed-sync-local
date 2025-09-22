# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0127.1");
  script_cve_id("CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9381", "CVE-2016-9776", "CVE-2016-9845", "CVE-2016-9846", "CVE-2016-9907", "CVE-2016-9908", "CVE-2016-9911", "CVE-2016-9912", "CVE-2016-9913", "CVE-2016-9921", "CVE-2016-9922");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-25 16:05:00 +0000 (Wed, 25 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0127-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0127-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170127-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937125");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-January/002561.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2017:0127-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"qemu was updated to fix several issues.

These security issues were fixed:

- CVE-2016-9102: Memory leak in the v9fs_xattrcreate function in hw/9pfs/9p.c in allowed local guest OS administrators to cause a denial of service (memory consumption and QEMU process crash) via a large number of Txattrcreate messages with the same fid number (bsc#1014256).
- CVE-2016-9103: The v9fs_xattrcreate function in hw/9pfs/9p.c in allowed local guest OS administrators to obtain sensitive host heap memory information by reading xattribute values writing to them (bsc#1007454).
- CVE-2016-9381: Improper processing of shared rings allowing guest administrators take over the qemu process, elevating their privilege to that of the qemu process (bsc#1009109)
- CVE-2016-9776: The ColdFire Fast Ethernet Controller emulator support was vulnerable to an infinite loop issue while receiving packets in 'mcf_fec_receive'. A privileged user/process inside guest could have used this issue to crash the Qemu process on the host leading to DoS (bsc#1013285).
- CVE-2016-9845: The Virtio GPU Device emulator support as vulnerable to an information leakage issue while processing the 'VIRTIO_GPU_CMD_GET_CAPSET_INFO' command. A guest user/process could have used this flaw to leak contents of the host memory (bsc#1013767).
- CVE-2016-9846: The Virtio GPU Device emulator support was vulnerable to a memory leakage issue while updating the cursor data in update_cursor_data_virgl. A guest user/process could have used this flaw to leak host memory bytes, resulting in DoS for the host (bsc#1013764).
- CVE-2016-9907: The USB redirector usb-guest support was vulnerable to a memory leakage flaw when destroying the USB redirector in 'usbredir_handle_destroy'. A guest user/process could have used this issue to leak host memory, resulting in DoS for a host (bsc#1014109).
- CVE-2016-9908: The Virtio GPU Device emulator support was vulnerable to an information leakage issue while processing the 'VIRTIO_GPU_CMD_GET_CAPSET' command. A guest user/process could have used this flaw to leak contents of the host memory (bsc#1014514).
- CVE-2016-9911: The USB EHCI Emulation support was vulnerable to a memory leakage issue while processing packet data in 'ehci_init_transfer'. A guest user/process could have used this issue to leak host memory, resulting in DoS for the host (bsc#1014111).
- CVE-2016-9912: The Virtio GPU Device emulator support was vulnerable to a memory leakage issue while destroying gpu resource object in 'virtio_gpu_resource_destroy'. A guest user/process could have used this flaw to leak host memory bytes, resulting in DoS for the host (bsc#1014112).
- CVE-2016-9913: VirtFS was vulnerable to memory leakage issue via its '9p-handle' or '9p-proxy' backend drivers. A privileged user inside guest could have used this flaw to leak host memory, thus affecting other services on the host and/or potentially crash the Qemu ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.9.1~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.6.2~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.9.1~39.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.6.2~39.1", rls:"SLES12.0SP2"))) {
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
