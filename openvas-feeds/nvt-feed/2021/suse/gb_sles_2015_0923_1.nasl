# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0923.1");
  script_cve_id("CVE-2015-2751", "CVE-2015-2752", "CVE-2015-3340", "CVE-2015-3456");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0923-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150923-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929339");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-May/001398.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2015:0923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XEN was updated to fix two security issues and bugs.

Security issues fixed:
* CVE-2015-3340: Xen did not initialize certain fields, which allowed
 certain remote service domains to obtain sensitive information from
 memory via a (1) XEN_DOMCTL_gettscinfo or (2) XEN_SYSCTL_getdomaininfolist
 request.

* CVE-2015-2751: Xen, when using toolstack disaggregation, allowed remote
 domains with partial management control to cause a denial of service
 (host lock) via unspecified domctl operations.

* CVE-2015-2752: The XEN_DOMCTL_memory_mapping hypercall in Xen, when
 using a PCI passthrough device, was not preemptable, which allowed local
 x86 HVM domain users to cause a denial of service (host CPU consumption)
 via a crafted request to the device model (qemu-dm).

* CVE-2015-3456: Fixed a buffer overflow in the floppy drive emulation, which could be used
 to denial of service attacks or potential code execution against the host.

Bugs fixed:
- xentop: Fix memory leak on read failure");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.2_04~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.2_04~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.2_04_k3.12.39_47~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.2_04~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.2_04~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.2_04~18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.2_04~18.1", rls:"SLES12.0"))) {
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
