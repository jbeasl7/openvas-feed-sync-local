# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2963.1");
  script_cve_id("CVE-2016-9602", "CVE-2016-9603", "CVE-2017-10664", "CVE-2017-10806", "CVE-2017-11334", "CVE-2017-11434", "CVE-2017-13672", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15289", "CVE-2017-5579", "CVE-2017-5973", "CVE-2017-6505", "CVE-2017-7471", "CVE-2017-7493", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8309", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9375", "CVE-2017-9503");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:51 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 14:29:43 +0000 (Thu, 06 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2963-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2963-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172963-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038396");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063122");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-November/003386.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2017:2963-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kvm fixes several issues.

These security issues were fixed:

- CVE-2016-9602: The VirtFS host directory sharing via Plan 9 File System(9pfs) support was vulnerable to an improper link following issue which allowed a privileged user inside guest to access host file system beyond the shared folder and potentially escalating their privileges on a host (bsc#1020427)
- CVE-2016-9603: A privileged user within the guest VM could have caused a heap overflow in the device model process, potentially escalating their privileges to that of the device model process (bsc#1028656)
- CVE-2017-10664: qemu-nbd did not ignore SIGPIPE, which allowed remote attackers to cause a denial of service (daemon crash) by disconnecting during a server-to-client reply attempt (bsc#1046636)
- CVE-2017-10806: Stack-based buffer overflow allowed local guest OS users to cause a denial of service (QEMU process crash) via vectors related to logging debug messages (bsc#1047674).
- CVE-2017-11334: The address_space_write_continue function allowed local guest OS privileged users to cause a denial of service (out-of-bounds access and guest instance crash) by leveraging use of qemu_map_ram_ptr to access guest ram block area (bsc#1048902).
- CVE-2017-11434: The dhcp_decode function in slirp/bootp.c allowed local guest OS users to cause a denial of service (out-of-bounds read) via a crafted DHCP options string (bsc#1049381)
- CVE-2017-13672: The VGA display emulator support allowed local guest OS privileged users to cause a denial of service (out-of-bounds read and QEMU process crash) via vectors involving display update (bsc#1056334).
- CVE-2017-14167: Integer overflow in the load_multiboot function allowed local guest OS users to execute arbitrary code on the host via crafted multiboot header address values, which trigger an out-of-bounds write (bsc#1057585).
- CVE-2017-15038: Race condition in the v9fs_xattrwalk function local guest OS users to obtain sensitive information from host heap memory via vectors related to reading extended attributes (bsc#1062069).
- CVE-2017-15289: The mode4and5 write functions allowed local OS guest privileged users to cause a denial of service (out-of-bounds write access and Qemu process crash) via vectors related to dst calculation (bsc#1063122).
- CVE-2017-5579: The 16550A UART serial device emulation support was vulnerable to a memory leakage issue allowing a privileged user to cause a DoS and/or potentially crash the Qemu process on the host (bsc#1021741)
- CVE-2017-5973: A infinite loop while doing control transfer in xhci_kick_epctx allowed privileged user inside the guest to crash the host process resulting in DoS (bsc#1025109)
- CVE-2017-6505: The ohci_service_ed_list function allowed local guest OS users to cause a denial of service (infinite loop) via vectors involving the number of link endpoint list descriptors (bsc#1028184)
- CVE-2017-7471: The VirtFS ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~60.3.1", rls:"SLES11.0SP4"))) {
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
