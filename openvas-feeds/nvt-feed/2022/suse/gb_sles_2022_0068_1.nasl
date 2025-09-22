# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0068.1");
  script_cve_id("CVE-2018-25020", "CVE-2019-15126", "CVE-2020-27820", "CVE-2021-0920", "CVE-2021-0935", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-33098", "CVE-2021-4002", "CVE-2021-43975", "CVE-2021-43976", "CVE-2021-45485", "CVE-2021-45486");
  script_tag(name:"creation_date", value:"2022-01-16 03:26:17 +0000 (Sun, 16 Jan 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-13 16:34:33 +0000 (Mon, 13 Dec 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0068-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0068-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220068-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194094");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-January/010003.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0068-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated.

The following security bugs were fixed:

- CVE-2019-15126: Fixed a vulnerability in Broadcom and Cypress Wi-Fi chips, used in RPi family of devices aka 'Kr00k'. (bsc#1167162)
- CVE-2021-33098: Fixed a potential denial of service in Intel(R) Ethernet ixgbe driver due to improper input validation. (bsc#1192877)
- CVE-2021-0935: Fixed out of bounds write due to a use after free which could lead to local escalation of privilege with System execution privileges needed in ip6_xmit. (bsc#1192032)
- CVE-2018-25020: Fixed an issue in the BPF subsystem in the Linux kernel mishandled situations with a long jump over an instruction sequence where inner instructions require substantial expansions into multiple BPF instructions, leading to an overflow. (bsc#1193575)
- CVE-2021-0920: Fixed a local privilege escalation due to an use after free bug in unix_gc. (bsc#1193731)
- CVE-2021-45485: Fixed an information leak because of certain use of a hash table which use IPv6 source addresses. (bsc#1194094)
- CVE-2021-45486: Fixed an information leak because the hash table is very small in net/ipv4/route.c. (bsc#1194087)
- CVE-2021-28715: Fixed an issue where a guest could force Linux netback driver to hog large amounts of kernel memory by do not queueing unlimited number of packages. (bsc#1193442)
- CVE-2021-28714: Fixed an issue where a guest could force Linux netback driver to hog large amounts of kernel memory by fixing rx queue stall detection. (bsc#1193442)
- CVE-2021-28713: Fixed a rogue backends that could cause DoS of guests via high frequency events by hardening hvc_xen against event channel storms. (bsc#1193440)
- CVE-2021-28712: Fixed a rogue backends that could cause DoS of guests via high frequency events by hardening netfront against event channel storms. (bsc#1193440)
- CVE-2021-28711: Fixed a rogue backends that could cause DoS of guests via high frequency events by hardening blkfront against event channel storms. (bsc#1193440)
- CVE-2021-43975: Fixed a flaw in hw_atl_utils_fw_rpc_wait that could allow an attacker (who can introduce a crafted device) to trigger an out-of-bounds write via a crafted length value. (bsc#1192845)
- CVE-2021-43976: Fixed a flaw that could allow an attacker (who can connect a crafted USB device) to cause a denial of service. (bsc#1192847)
- CVE-2021-4002: Added a missing TLB flush that could lead to leak or corruption of data in hugetlbfs. (bsc#1192946)
- CVE-2020-27820: Fixed a vulnerability where a use-after-frees in nouveau's postclose() handler could happen if removing device. (bsc#1179599)

The following non-security bugs were fixed:

- blk-mq: do not deactivate hctx if managed irq isn't used (bsc#1185762).
- cifs: Add new mount parameter 'acdirmax' to allow caching directory metadata (bsc#1190317).
- cifs: Add new parameter 'acregmax' for distinct file and directory metadata timeout ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.106.1", rls:"SLES12.0SP5"))) {
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
