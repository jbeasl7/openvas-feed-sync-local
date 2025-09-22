# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1855.1");
  script_cve_id("CVE-2017-13305", "CVE-2017-18241", "CVE-2017-18249", "CVE-2018-1000199", "CVE-2018-1000204", "CVE-2018-1065", "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-1094", "CVE-2018-1130", "CVE-2018-3665", "CVE-2018-5803", "CVE-2018-5848", "CVE-2018-7492");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 18:41:15 +0000 (Fri, 03 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1855-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1855-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181855-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973378");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-June/004236.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1855-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-5848: In the function wmi_set_ie(), the length validation code did
 not handle unsigned integer overflow properly. As a result, a large value of
 the 'ie_len' argument could have caused a buffer overflow (bnc#1097356)
- CVE-2018-1000204: Prevent infoleak caused by incorrect handling of the SG_IO
 ioctl (bsc#1096728).
- CVE-2017-18249: The add_free_nid function did not properly track an allocated
 nid, which allowed local users to cause a denial of service (race condition) or
 possibly have unspecified other impact via concurrent threads (bnc#1087036)
- CVE-2018-3665: Prevent disclosure of FPU registers (including XMM and AVX
 registers) between processes. These registers might contain encryption keys
 when doing SSE accelerated AES enc/decryption (bsc#1087086)
- CVE-2017-18241: Prevent a NULL pointer dereference by using a noflush_merge
 option that triggers a NULL value for a flush_cmd_control data structure
 (bnc#1086400)
- CVE-2017-13305: Prevent information disclosure vulnerability in
 encrypted-keys (bsc#1094353).
- CVE-2018-1093: The ext4_valid_block_bitmap function allowed attackers to
 cause a denial of service (out-of-bounds read and system crash) via a crafted
 ext4 image because balloc.c and ialloc.c did not validate bitmap block numbers
 (bsc#1087095).
- CVE-2018-1094: The ext4_fill_super function did not always initialize the
 crc32c checksum driver, which allowed attackers to cause a denial of service
 (ext4_xattr_inode_hash NULL pointer dereference and system crash) via a crafted
 ext4 image (bsc#1087007).
- CVE-2018-1092: The ext4_iget function mishandled the case of a root directory
 with a zero i_links_count, which allowed attackers to cause a denial of service
 (ext4_process_freed_data NULL pointer dereference and OOPS) via a crafted ext4
 image (bsc#1087012).
- CVE-2018-1130: NULL pointer dereference in dccp_write_xmit() function that
 allowed a local user to cause a denial of service by a number of certain
 crafted system calls (bsc#1092904).
- CVE-2018-1065: The netfilter subsystem mishandled the case of a rule blob
 that contains a jump but lacks a user-defined chain, which allowed local users
 to cause a denial of service (NULL pointer dereference) by leveraging the
 CAP_NET_RAW or CAP_NET_ADMIN capability (bsc#1083650).
- CVE-2018-5803: Prevent error in the '_sctp_make_chunk()' function when
 handling SCTP packets length that could have been exploited to cause a kernel
 crash (bnc#1083900).
- CVE-2018-7492: Prevent NULL pointer dereference in the net/rds/rdma.c
 __rds_rdma_map() function that allowed local attackers to cause a system panic
 and a denial-of-service, related to RDS_GET_MR and RDS_GET_MR_FOR_DEST
 (bsc#1082962).
- CVE-2018-1000199: Prevent vulnerability in modify_user_hw_breakpoint() ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.85.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.85.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.85.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.121~92.85.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.85.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.85.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.85.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.85.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_85-default", rpm:"kgraft-patch-4_4_121-92_85-default~1~3.5.1", rls:"SLES12.0SP2"))) {
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
