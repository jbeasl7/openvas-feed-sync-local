# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1081.1");
  script_cve_id("CVE-2016-9603", "CVE-2017-2633", "CVE-2017-6414", "CVE-2017-6505", "CVE-2017-7228");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-06 14:29:43 +0000 (Thu, 06 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1081-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1081-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171081-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030442");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-April/002822.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:1081-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

These security issues were fixed:

- CVE-2017-7228: Broken check in memory_exchange() permited PV guest breakout (bsc#1030442).
- XSA-206: Unprivileged guests issuing writes to xenstore were able to stall progress of the control domain or driver domain, possibly leading to a Denial of Service (DoS) of the entire host (bsc#1030144).
- CVE-2016-9603: A privileged user within the guest VM can cause a heap overflow in the device model process, potentially escalating their privileges to that of the device model process (bsc#1028655).
- CVE-2017-6414: Memory leak in the vcard_apdu_new function in card_7816.c in libcacard allowed local guest OS users to cause a denial of service (host memory consumption) via vectors related to allocating a new APDU object (bsc#1027570).
- CVE-2017-6505: The ohci_service_ed_list function in hw/usb/hcd-ohci.c allowed local guest OS users to cause a denial of service (infinite loop) via vectors involving the number of link endpoint list descriptors (bsc#1028235).
- CVE-2017-2633: The VNC display driver support was vulnerable to an out-of-bounds memory access issue. A user/process inside guest could use this flaw to cause DoS (bsc#1026636).

These non-security issues were fixed:

- bsc#1022555: Timeout in 'execution of /etc/xen/scripts/block add'
- bsc#1029827: Forward port xenstored");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_16~54.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_16~54.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_16_3.0.101_97~54.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.4.4_16_3.0.101_97~54.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_16~54.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_16~54.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_16~54.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_16~54.1", rls:"SLES11.0SP4"))) {
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
