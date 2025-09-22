# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2674.1");
  script_cve_id("CVE-2017-16808", "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466", "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470", "CVE-2018-14879", "CVE-2018-14880", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16301", "CVE-2018-16451", "CVE-2018-16452", "CVE-2019-1010220", "CVE-2019-15166", "CVE-2019-15167");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:15 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-07 17:37:15 +0000 (Mon, 07 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2674-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2674-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192674-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump' package(s) announced via the SUSE-SU-2019:2674-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tcpdump fixes the following issues:
CVE-2017-16808: Fixed a heap-based buffer over-read related to aoe_print
 and lookup_emem (bsc#1068716 bsc#1153098).

CVE-2018-10103: Fixed a mishandling of the printing of SMB data
 (bsc#1153098).

CVE-2018-10105: Fixed a mishandling of the printing of SMB data
 (bsc#1153098).

CVE-2018-14461: Fixed a buffer over-read in print-ldp.c:ldp_tlv_print
 (bsc#1153098).

CVE-2018-14462: Fixed a buffer over-read in print-icmp.c:icmp_print
 (bsc#1153098).

CVE-2018-14463: Fixed a buffer over-read in print-vrrp.c:vrrp_print
 (bsc#1153098).

CVE-2018-14464: Fixed a buffer over-read in
 print-lmp.c:lmp_print_data_link_subobjs (bsc#1153098).

CVE-2018-14465: Fixed a buffer over-read in print-rsvp.c:rsvp_obj_print
 (bsc#1153098).

CVE-2018-14466: Fixed a buffer over-read in print-rx.c:rx_cache_find
 (bsc#1153098).

CVE-2018-14467: Fixed a buffer over-read in
 print-bgp.c:bgp_capabilities_print (bsc#1153098).

CVE-2018-14468: Fixed a buffer over-read in print-fr.c:mfr_print
 (bsc#1153098).

CVE-2018-14469: Fixed a buffer over-read in print-isakmp.c:ikev1_n_print
 (bsc#1153098).

CVE-2018-14470: Fixed a buffer over-read in print-babel.c:babel_print_v2
 (bsc#1153098).

CVE-2018-14879: Fixed a buffer overflow in the command-line argument
 parser (bsc#1153098).

CVE-2018-14880: Fixed a buffer over-read in the OSPFv3 parser
 (bsc#1153098).

CVE-2018-14881: Fixed a buffer over-read in the BGP parser (bsc#1153098).

CVE-2018-14882: Fixed a buffer over-read in the ICMPv6 parser
 (bsc#1153098).

CVE-2018-16227: Fixed a buffer over-read in the IEEE 802.11 parser in
 print-802_11.c for the Mesh Flags subfield (bsc#1153098).

CVE-2018-16228: Fixed a buffer over-read in the HNCP parser
 (bsc#1153098).

CVE-2018-16229: Fixed a buffer over-read in the DCCP parser
 (bsc#1153098).

CVE-2018-16230: Fixed a buffer over-read in the BGP parser in
 print-bgp.c:bgp_attr_print (bsc#1153098).

CVE-2018-16300: Fixed an unlimited recursion in the BGP parser that
 allowed denial-of-service by stack consumption (bsc#1153098).

CVE-2018-16301: Fixed a buffer overflow (bsc#1153332 bsc#1153098).

CVE-2018-16451: Fixed several buffer over-reads in
 print-smb.c:print_trans() for \MAILSLOT\BROWSE and \PIPE\LANMAN
 (bsc#1153098).

CVE-2018-16452: Fixed a stack exhaustion in smbutil.c:smb_fdata
 (bsc#1153098).

CVE-2019-15166: Fixed a bounds check in lmp_print_data_link_subobjs
 (bsc#1153098).

CVE-2019-15167: Fixed a vulnerability in VRRP (bsc#1153098).");

  script_tag(name:"affected", value:"'tcpdump' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.2~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump-debuginfo", rpm:"tcpdump-debuginfo~4.9.2~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump-debugsource", rpm:"tcpdump-debugsource~4.9.2~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.2~3.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump-debuginfo", rpm:"tcpdump-debuginfo~4.9.2~3.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpdump-debugsource", rpm:"tcpdump-debugsource~4.9.2~3.9.1", rls:"SLES15.0SP1"))) {
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
