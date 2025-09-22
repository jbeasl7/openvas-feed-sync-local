# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2628.1");
  script_cve_id("CVE-2014-7815", "CVE-2015-6815", "CVE-2016-2391", "CVE-2016-2392", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6490", "CVE-2016-7116");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:03 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-14 16:05:16 +0000 (Tue, 14 Jun 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2628-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2628-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162628-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996441");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-October/002352.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2016:2628-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kvm was updated to fix 16 security issues.

These security issues were fixed:
- CVE-2015-6815: e1000 NIC emulation support was vulnerable to an infinite loop issue. A privileged user inside guest could have used this flaw to crash the Qemu instance resulting in DoS. (bsc#944697).
- CVE-2016-2391: The ohci_bus_start function in the USB OHCI emulation support (hw/usb/hcd-ohci.c) in QEMU allowed local guest OS administrators to cause a denial of service (NULL pointer dereference and QEMU process crash) via vectors related to multiple eof_timers (bsc#967013).
- CVE-2016-2392: The is_rndis function in the USB Net device emulator (hw/usb/dev-network.c) in QEMU did not properly validate USB configuration descriptor objects, which allowed local guest OS administrators to cause a denial of service (NULL pointer dereference and QEMU process crash) via vectors involving a remote NDIS control message packet (bsc#967012).
- CVE-2016-4453: The vmsvga_fifo_run function in hw/display/vmware_vga.c in QEMU allowed local guest OS administrators to cause a denial of service (infinite loop and QEMU process crash) via a VGA command (bsc#982223).
- CVE-2016-4454: The vmsvga_fifo_read_raw function in hw/display/vmware_vga.c in QEMU allowed local guest OS administrators to obtain sensitive host memory information or cause a denial of service (QEMU process crash) by changing FIFO registers and issuing a VGA command, which triggers an out-of-bounds read (bsc#982222).
- CVE-2016-5105: The megasas_dcmd_cfg_read function in hw/scsi/megasas.c in QEMU, when built with MegaRAID SAS 8708EM2 Host Bus Adapter emulation support, used an uninitialized variable, which allowed local guest administrators to read host memory via vectors involving a MegaRAID Firmware Interface (MFI) command (bsc#982017).
- CVE-2016-5106: The megasas_dcmd_set_properties function in hw/scsi/megasas.c in QEMU, when built with MegaRAID SAS 8708EM2 Host Bus Adapter emulation support, allowed local guest administrators to cause a denial of service (out-of-bounds write access) via vectors involving a MegaRAID Firmware Interface (MFI) command (bsc#982018).
- CVE-2016-5107: The megasas_lookup_frame function in QEMU, when built with MegaRAID SAS 8708EM2 Host Bus Adapter emulation support, allowed local guest OS administrators to cause a denial of service (out-of-bounds read and crash) via unspecified vectors (bsc#982019).
- CVE-2016-5126: Heap-based buffer overflow in the iscsi_aio_ioctl function in block/iscsi.c in QEMU allowed local guest OS users to cause a denial of service (QEMU process crash) or possibly execute arbitrary code via a crafted iSCSI asynchronous I/O ioctl call (bsc#982285).
- CVE-2016-5238: The get_cmd function in hw/scsi/esp.c in QEMU allowed local guest OS administrators to cause a denial of service (out-of-bounds write and QEMU process crash) via vectors related to reading from the information transfer buffer in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kvm' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~47.1", rls:"SLES11.0SP4"))) {
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
