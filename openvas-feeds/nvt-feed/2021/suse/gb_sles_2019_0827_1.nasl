# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0827.1");
  script_cve_id("CVE-2017-13672", "CVE-2018-10839", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18438", "CVE-2018-18849", "CVE-2018-19665", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-19967", "CVE-2019-6778", "CVE-2019-9824");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-24 03:55:35 +0000 (Sat, 24 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0827-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0827-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190827-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
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
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129623");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-April/005275.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2019:0827-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

Security issues fixed:

- CVE-2019-6778: Fixed a heap buffer overflow in tcp_emu() found in slirp (bsc#1123157).
- CVE-2017-13672: Fixed an out of bounds read access during display update (bsc#1056336).
- Fixed an issue which could allow malicious or buggy guests with passed through PCI devices to be able to
 escalate their privileges, crash the host, or access data belonging to other guests. Additionally memory
 leaks were also possible (bsc#1126140)
- Fixed a race condition issue which could allow malicious PV guests to escalate their privilege to that
 of the hypervisor (bsc#1126141).
- CVE-2018-18849: Fixed an out of bounds msg buffer access which could lead to denial of service (bsc#1114423).
- Fixed an issue which could allow a malicious unprivileged guest userspace process to escalate its privilege
 to that of other userspace processes in the same guest and potentially thereby to that
 of the guest operating system (bsc#1126201).
- CVE-2018-17958: Fixed an integer overflow leading to a buffer overflow in the
 rtl8139 component (bsc#1111007)
- CVE-2018-19967: Fixed HLE constructs that allowed guests to lock up the host,
 resulting in a Denial of Service (DoS). (XSA-282) (bsc#1114988)
- CVE-2018-19665: Fixed an integer overflow resulting in memory corruption in
 various Bluetooth functions, allowing this to crash qemu process resulting in
 Denial of Service (DoS). (bsc#1117756).
- CVE-2019-9824: Fixed an information leak in SLiRP networking implementation which could allow a user/process
 to read uninitialised stack memory contents (bsc#1129623).
- CVE-2018-19961, CVE-2018-19962: Fixed an issue related to insufficient TLB
 flushing with AMD IOMMUs, which potentially allowed a guest to escalate its
 privileges, may cause a Denial of Service (DoS) affecting the entire host, or
 may be able to access data it is not supposed to access. (XSA-275)
 (bsc#1115040)
- CVE-2018-19966: Fixed an issue related to a previous fix for XSA-240, which
 conflicted with shadow paging and allowed a guest to cause Xen to crash,
 resulting in a Denial of Service (DoS) (XSA-280) (bsc#1115047).
- CVE-2018-10839: Fixed an integer overflow leading to a buffer overflow in
 the ne2000 component (bsc#1110924).
- CVE-2018-19965: Fixed an issue related to the INVPCID instruction in case
 non-canonical addresses are accessed, which may allow a guest to cause Xen to
 crash, resulting in a Denial of Service (DoS) affecting the entire host.
 (XSA-279) (bsc#1115045).
- Fixed an issue which could allow malicious 64bit PV guests to cause a host crash (bsc#1127400).
- Fixed an issue which could allow malicious PV guests may cause a host crash or
 gain access to data pertaining to other guests.Additionally, vulnerable configurations
 are likely to be unstable even in the absence of an attack (bsc#1126198).
- Fixed multiple access violations introduced by ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_40~22.77.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_40~22.77.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_40_k3.12.61_52.146~22.77.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_40~22.77.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_40~22.77.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_40~22.77.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_40~22.77.1", rls:"SLES12.0"))) {
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
