# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2005.1");
  script_cve_id("CVE-2013-7446", "CVE-2015-8019", "CVE-2015-8816", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-3134", "CVE-2016-4470", "CVE-2016-4565");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-24 13:35:40 +0000 (Tue, 24 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2005-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162005-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984764");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002191.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel Live Patch 8 for SLE 12' package(s) announced via the SUSE-SU-2016:2005-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 3.12.48-52_27 fixes several issues.

The following security bugs were fixed:
- CVE-2016-4470: The key_reject_and_link function in security/keys/key.c in the Linux kernel did not ensure that a certain data structure is initialized, which allowed local users to cause a denial of service (system crash) via vectors involving a crafted keyctl request2 command (bsc#984764).
- CVE-2016-1583: The ecryptfs_privileged_open function in fs/ecryptfs/kthread.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (stack memory consumption) via vectors involving crafted mmap calls for /proc pathnames, leading to recursive pagefault handling (bsc#983144).
- CVE-2016-4565: The InfiniBand (aka IB) stack in the Linux kernel incorrectly relied on the write system call, which allowed local users to cause a denial of service (kernel memory write operation) or possibly have unspecified other impact via a uAPI interface (bsc#980883).
- CVE-2016-0758: Integer overflow in lib/asn1_decoder.c in the Linux kernel allowed local users to gain privileges via crafted ASN.1 data (bsc#980856).
- CVE-2015-8019: The skb_copy_and_csum_datagram_iovec function in net/core/datagram.c in the Linux kernel did not accept a length argument, which allowed local users to cause a denial of service (memory corruption) or possibly have unspecified other impact via a write system call followed by a recvmsg system call (bsc#979078).
- CVE-2016-2053: The asn1_ber_decoder function in lib/asn1_decoder.c in the Linux kernel allowed attackers to cause a denial of service (panic) via an ASN.1 BER file that lacks a public key, leading to mishandling by the public_key_verify_signature function in crypto/asymmetric_keys/public_key.c (bsc#979074).
- CVE-2015-8816: The hub_activate function in drivers/usb/core/hub.c in the Linux kernel did not properly maintain a hub-interface data structure, which allowed physically proximate attackers to cause a denial of service (invalid memory access and system crash) or possibly have unspecified other impact by unplugging a USB hub device (bsc#979064).
- CVE-2016-3134: The netfilter subsystem in the Linux kernel did not validate certain offset fields, which allowed local users to gain privileges or cause a denial of service (heap memory corruption) via an IPT_SO_SET_REPLACE setsockopt call (bsc#971793).
- CVE-2013-7446: Use-after-free vulnerability in net/unix/af_unix.c in the Linux kernel allowed local users to bypass intended AF_UNIX socket permissions or cause a denial of service (panic) via crafted epoll_ctl calls (bsc#973570, bsc#955837).");

  script_tag(name:"affected", value:"'Linux Kernel Live Patch 8 for SLE 12' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_48-52_27-default", rpm:"kgraft-patch-3_12_48-52_27-default~5~2.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_48-52_27-xen", rpm:"kgraft-patch-3_12_48-52_27-xen~5~2.2", rls:"SLES12.0"))) {
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
