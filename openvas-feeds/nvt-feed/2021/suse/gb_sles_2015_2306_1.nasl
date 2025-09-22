# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2306.1");
  script_cve_id("CVE-2015-5307", "CVE-2015-7504", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-7972", "CVE-2015-8104", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8345");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:09 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-24 14:39:31 +0000 (Tue, 24 Oct 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2306-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2306-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152306-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956832");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-December/001742.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2015:2306-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following security issues:

- bsc#956832 - CVE-2015-8345: xen: qemu: net: eepro100:
 infinite loop in processing command block list

- bsc#956408 - CVE-2015-8339, CVE-2015-8340: xen:
 XENMEM_exchange error handling issues (XSA-159)
 xsa159.patch
- bsc#956411 - CVE-2015-7504: xen: heap buffer overflow
 vulnerability in pcnet emulator (XSA-162)

- bsc#954405 - CVE-2015-8104: Xen: guest to host DoS by
 triggering an infinite loop in microcode via #DB exception
- bsc#953527 - CVE-2015-5307: kernel: kvm/xen: x86: avoid
 guest->host DOS by intercepting #AC (XSA-156)

- bsc#950704 - CVE-2015-7970: xen: x86: Long latency
 populate-on-demand operation is not preemptible (XSA-150)

- bsc#951845 - CVE-2015-7972: xen: x86: populate-on-demand
 balloon size inaccuracy can crash guests (XSA-153)

- bsc#950703 - CVE-2015-7969: xen: leak of main per-domain
 vcpu pointer array (DoS) (XSA-149)
- bsc#950705 - CVE-2015-7969: xen: x86: leak of per-domain
 profiling-related vcpu pointer array (DoS) (XSA-151)
- bsc#950706 - CVE-2015-7971: xen: x86: some pmu and
 profiling hypercalls log without rate limiting (XSA-152)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.6_08~23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.1.6_08~23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.1.6_08~23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.1.6_08~23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.6_08_3.0.101_0.7.37~23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.1.6_08_3.0.101_0.7.37~23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.1.6_08_3.0.101_0.7.37~23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.1.6_08~23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.1.6_08~23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.1.6_08~23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.1.6_08~23.1", rls:"SLES11.0SP2"))) {
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
