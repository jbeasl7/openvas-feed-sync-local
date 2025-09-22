# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2541.1");
  script_cve_id("CVE-2017-10664", "CVE-2017-10806", "CVE-2017-11334", "CVE-2017-11434", "CVE-2017-12135", "CVE-2017-12137", "CVE-2017-12855", "CVE-2017-14316", "CVE-2017-14317", "CVE-2017-14319");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-23 00:37:30 +0000 (Sat, 23 Sep 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2541-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2541-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172541-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056282");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-September/003253.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:2541-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.

These security issues were fixed:

- CVE-2017-12135: Unbounded recursion in grant table code allowed a malicious
 guest to crash the host or potentially escalate privileges/leak information
 (XSA-226, bsc#1051787).
- CVE-2017-12137: Incorrectly-aligned updates to pagetables allowed for
 privilege escalation (XSA-227, bsc#1051788).
- CVE-2017-11334: The address_space_write_continue function in exec.c allowed
 local guest OS privileged users to cause a denial of service (out-of-bounds
 access and guest instance crash) by leveraging use of qemu_map_ram_ptr to
 access guest ram block area (bsc#1048920).
- CVE-2017-11434: The dhcp_decode function in slirp/bootp.c allowed local guest
 OS users to cause a denial of service (out-of-bounds read) via a crafted DHCP
 options string (bsc#1049578).
- CVE-2017-10806: Stack-based buffer overflow in hw/usb/redirect.c allowed
 local guest OS users to cause a denial of service via vectors related to
 logging debug messages (bsc#1047675).
- CVE-2017-10664: qemu-nbd did not ignore SIGPIPE, which allowed remote
 attackers to cause a denial of service (daemon crash) by disconnecting during
 a server-to-client reply attempt (bsc#1046637).
- CVE-2017-12855: Premature clearing of GTF_writing / GTF_reading lead to
 potentially leaking sensitive information (XSA-230, bsc#1052686).
- CVE-2017-14316: Missing bound check in function `alloc_heap_pages` for an
 internal array allowed attackers using crafted hypercalls to execute
 arbitrary code within Xen (XSA-231, bsc#1056278)
- CVE-2017-14317: A race in cxenstored may have cause a double-free allowind for
 DoS of the xenstored daemon (XSA-233, bsc#1056281).
- CVE-2017-14319: An error while handling grant mappings allowed malicious or
 buggy x86 PV guest to escalate its privileges or crash the hypervisor (XSA-234,
 bsc#1056282).

These non-security issues were fixed:

- bsc#1002573: Optimized LVM functions in block-dmmd block-dmmd
- bsc#1032598: Prevent removal of NVME devices
- bsc#1037413: Support for newer intel cpu's, mwait-idle driver and skylake");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_22~22.51.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_22~22.51.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_22_k3.12.61_52.89~22.51.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_22~22.51.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_22~22.51.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_22~22.51.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_22~22.51.2", rls:"SLES12.0"))) {
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
