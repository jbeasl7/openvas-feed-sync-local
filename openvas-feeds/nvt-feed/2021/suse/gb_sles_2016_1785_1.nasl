# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1785.1");
  script_cve_id("CVE-2014-3615", "CVE-2014-3689", "CVE-2014-9718", "CVE-2015-3214", "CVE-2015-5239", "CVE-2015-5278", "CVE-2015-5279", "CVE-2015-5745", "CVE-2015-6855", "CVE-2015-7295", "CVE-2015-7549", "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2016-1568", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2198", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-12 17:44:22 +0000 (Thu, 12 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1785-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161785-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980723");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-July/002154.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2016:1785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kvm was updated to fix 33 security issues.

These security issues were fixed:
- CVE-2016-4439: Avoid OOB access in 53C9X emulation (bsc#980711)
- CVE-2016-4441: Avoid OOB access in 53C9X emulation (bsc#980723)
- CVE-2016-3710: Fixed VGA emulation based OOB access with potential for guest escape (bsc#978158)
- CVE-2016-3712: Fixed VGa emulation based DOS and OOB read access exploit (bsc#978160)
- CVE-2016-4037: Fixed USB ehci based DOS (bsc#976109)
- CVE-2016-2538: Fixed potential OOB access in USB net device emulation (bsc#967969)
- CVE-2016-2841: Fixed OOB access / hang in ne2000 emulation (bsc#969350)
- CVE-2016-2858: Avoid potential DOS when using QEMU pseudo random number generator (bsc#970036)
- CVE-2016-2857: Fixed OOB access when processing IP checksums (bsc#970037)
- CVE-2016-4001: Fixed OOB access in Stellaris enet emulated nic (bsc#975128)
- CVE-2016-4002: Fixed OOB access in MIPSnet emulated controller (bsc#975136)
- CVE-2016-4020: Fixed possible host data leakage to guest from TPR access (bsc#975700)
- CVE-2015-3214: Fixed OOB read in i8254 PIC (bsc#934069)
- CVE-2014-9718: Fixed the handling of malformed or short ide PRDTs to avoid any opportunity for guest to cause DoS by abusing that interface (bsc#928393)
- CVE-2014-3689: Fixed insufficient parameter validation in rectangle functions (bsc#901508)
- CVE-2014-3615: The VGA emulator in QEMU allowed local guest users to read host memory by setting the display to a high resolution (bsc#895528).
- CVE-2015-5239: Integer overflow in vnc_client_read() and protocol_client_msg() (bsc#944463).
- CVE-2015-5278: Infinite loop in ne2000_receive() function (bsc#945989).
- CVE-2015-5279: Heap-based buffer overflow in the ne2000_receive function in hw/net/ne2000.c in QEMU allowed guest OS users to cause a denial of service (instance crash) or possibly execute arbitrary code via vectors related to receiving packets (bsc#945987).
- CVE-2015-5745: Buffer overflow in virtio-serial (bsc#940929).
- CVE-2015-6855: hw/ide/core.c in QEMU did not properly restrict the commands accepted by an ATAPI device, which allowed guest users to cause a denial of service or possibly have unspecified other impact via certain IDE commands, as demonstrated by a WIN_READ_NATIVE_MAX command to an empty drive, which triggers a divide-by-zero error and instance crash (bsc#945404).
- CVE-2015-7295: hw/virtio/virtio.c in the Virtual Network Device (virtio-net) support in QEMU, when big or mergeable receive buffers are not supported, allowed remote attackers to cause a denial of service (guest network consumption) via a flood of jumbo frames on the (1) tuntap or (2) macvtap interface (bsc#947159).
- CVE-2015-7549: PCI null pointer dereferences (bsc#958917).
- CVE-2015-8504: VNC floating point exception (bsc#958491).
- CVE-2015-8558: Infinite loop in ehci_advance_state resulting in DoS (bsc#959005).
- CVE-2015-8613: Wrong sized memset in megasas command ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~44.1", rls:"SLES11.0SP4"))) {
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
