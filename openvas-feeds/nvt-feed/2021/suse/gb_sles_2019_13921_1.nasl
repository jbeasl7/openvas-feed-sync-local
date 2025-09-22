# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.13921.1");
  script_cve_id("CVE-2017-13672", "CVE-2018-10839", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18438", "CVE-2018-18849", "CVE-2018-19665", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-19967");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:32 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-24 03:55:35 +0000 (Sat, 24 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:13921-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:13921-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201913921-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117756");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2019:13921-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

Security vulnerabilities fixed:

- CVE-2018-19961, CVE-2018-19962: Fixed an issue related to insufficient TLB
 flushing with AMD IOMMUs, which potentially allowed a guest to escalate its
 privileges, may cause a Denial of Service (DoS) affecting the entire host, or
 may be able to access data it is not supposed to access. (XSA-275)
 (bsc#1115040)
- CVE-2018-19965: Fixed an issue related to the INVPCID instruction in case
 non-canonical addresses are accessed, which may allow a guest to cause Xen to
 crash, resulting in a Denial of Service (DoS) affecting the entire host.
 (XSA-279) (bsc#1115045)
- CVE-2018-19966: Fixed an issue related to a previous fix for XSA-240, which
 conflicted with shadow paging and allowed a guest to cause Xen to crash,
 resulting in a Denial of Service (DoS) (XSA-280) (bsc#1115047)
- CVE-2018-19967: Fixed HLE constructs that allowed guests to lock up the host,
 resulting in a Denial of Service (DoS). (XSA-282) (bsc#1114988)
- CVE-2018-19665: Fixed an integer overflow resulting in memory corruption in
 various Bluetooth functions, allowing this to crash qemu process resulting in
 Denial of Service (DoS). (bsc#1117756).
- CVE-2018-18849: Fixed an out of bounds memory access in the LSI53C895A SCSI
 host bus adapter emulation, which allowed a user and/or process to crash the
 qemu process resulting in a Denial of Service (DoS). (bsc#1114423)
- Fixed an integer overflow in ccid_card_vscard_read(), which allowed for
 memory corruption. (bsc#1112188)
- CVE-2017-13672: Fixed an out of bounds read access during display update
 (bsc#1056336)
- CVE-2018-17958: Fixed an integer overflow leading to a buffer overflow in the
 rtl8139 component (bsc#1111007)
- CVE-2018-17962: Fixed an integer overflow leading to a buffer overflow in the
 pcnet component (bsc#1111011)
- CVE-2018-17963: Fixed an integer overflow in relation to large packet sizes,
 leading to a denial of service (DoS). (bsc#1111014)
- CVE-2018-10839: Fixed an integer overflow leading to a buffer overflow in
 the ne2000 component (bsc#1110924)

Other bugs fixed:

- Fixed an issue related to a domU hang on SLE12-SP3 HV (bsc#1108940)
- Upstream bug fixes (bsc#1027519)
- Fixed crashing VMs when migrating between dom0 hosts (bsc#1031382)
- Fixed an issue with xpti=no-dom0 not working as expected (bsc#1105528)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_38~61.40.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_38~61.40.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_38_3.0.101_108.84~61.40.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.4.4_38_3.0.101_108.84~61.40.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_38~61.40.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_38~61.40.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_38~61.40.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_38~61.40.1", rls:"SLES11.0SP4"))) {
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
