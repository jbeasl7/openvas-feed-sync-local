# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1445.1");
  script_cve_id("CVE-2014-0222", "CVE-2014-7815", "CVE-2015-5278", "CVE-2015-8743", "CVE-2016-2270", "CVE-2016-2271", "CVE-2016-2391", "CVE-2016-2841");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-30 20:55:28 +0000 (Fri, 30 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1445-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1445-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161445-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2016:1445-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xen was updated to fix the following security issues:
CVE-2016-2841: net: ne2000: infinite loop in ne2000_receive (bsc#969351)
CVE-2016-2391: usb: multiple eof_timers in ohci module leads to null pointer dereference (bsc#967101)
CVE-2016-2270: x86: inconsistent cachability flags on guest mappings (XSA-154) (bsc#965315)
CVE-2016-2271: VMX: guest user mode may crash guest with non-canonical RIP (XSA-170) (bsc#965317)
CVE-2015-5278: Infinite loop in ne2000_receive() function (bsc#964947)
CVE-2014-0222: qcow1: validate L2 table size to avoid integer overflows (bsc#964925)
CVE-2014-7815: vnc: insufficient bits_per_pixel from the client sanitization (bsc#962627)
CVE-2015-8743: ne2000: OOB memory access in ioport r/w functions (bsc#960726)
Security Issues:
CVE-2016-2841 CVE-2016-2391 CVE-2016-2270 CVE-2016-2271 CVE-2015-5278 CVE-2014-0222 CVE-2014-7815 CVE-2015-8743");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~3.2.3_17040_46~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.2.3_17040_46~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~3.2.3_17040_46~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~3.2.3_17040_46~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-ps", rpm:"xen-doc-ps~3.2.3_17040_46~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-bigsmp", rpm:"xen-kmp-bigsmp~3.2.3_17040_46_2.6.16.60_0.132.8~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-debug", rpm:"xen-kmp-debug~3.2.3_17040_46_2.6.16.60_0.132.8~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~3.2.3_17040_46_2.6.16.60_0.132.8~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdump", rpm:"xen-kmp-kdump~3.2.3_17040_46_2.6.16.60_0.132.8~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdumppae", rpm:"xen-kmp-kdumppae~3.2.3_17040_46_2.6.16.60_0.132.8~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-smp", rpm:"xen-kmp-smp~3.2.3_17040_46_2.6.16.60_0.132.8~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-vmi", rpm:"xen-kmp-vmi~3.2.3_17040_46_2.6.16.60_0.132.8~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-vmipae", rpm:"xen-kmp-vmipae~3.2.3_17040_46_2.6.16.60_0.132.8~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.2.3_17040_46~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~3.2.3_17040_46~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~3.2.3_17040_46~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~3.2.3_17040_46~0.25.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-ioemu", rpm:"xen-tools-ioemu~3.2.3_17040_46~0.25.1", rls:"SLES10.0SP4"))) {
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
