# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1147.1");
  script_cve_id("CVE-2016-9603", "CVE-2017-2633", "CVE-2017-6414", "CVE-2017-6505", "CVE-2017-7718", "CVE-2017-7980");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 14:29:43 +0000 (Thu, 06 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1147-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171147-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035483");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002838.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:1147-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.

These security issues were fixed:

- A malicious 64-bit PV guest may be able to access all of system memory, allowing for all of privilege escalation, host crashes, and information leaks by placing a IRET hypercall in the middle of a multicall batch (XSA-213, bsc#1034843)
- A malicious pair of guests may be able to access all of system memory, allowing for all of privilege escalation, host crashes, and information leaks because of a missing check when transfering pages via GNTTABOP_transfer (XSA-214, bsc#1034844).
- CVE-2017-7718: hw/display/cirrus_vga_rop.h allowed local guest OS privileged users to cause a denial of service (out-of-bounds read and QEMU process crash) via vectors related to copying VGA data via the cirrus_bitblt_rop_fwd_transp_ and cirrus_bitblt_rop_fwd_ functions (bsc#1034994).
- CVE-2016-9603: A privileged user within the guest VM could have caused a heap overflow in the device model process, potentially escalating their privileges to that of the device model process (bsc#1028655)

These non-security issues were fixed:

- bsc#1027519: Missing upstream bug fixes
- bsc#1015348: libvirtd does not start during boot
- bsc#1022555: Timeout in 'execution of /etc/xen/scripts/block add");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.5.5_10~22.14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.5.5_10~22.14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.5.5_10_k3.12.69_60.64.35~22.14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.5.5_10~22.14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.5.5_10~22.14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.5.5_10~22.14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.5.5_10~22.14.1", rls:"SLES12.0SP1"))) {
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
