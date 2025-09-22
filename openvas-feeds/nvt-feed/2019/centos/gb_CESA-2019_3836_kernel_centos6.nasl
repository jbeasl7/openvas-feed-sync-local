# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883131");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2018-12207", "CVE-2019-0154", "CVE-2019-3900", "CVE-2019-11135");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");
  script_tag(name:"creation_date", value:"2019-11-14 03:01:08 +0000 (Thu, 14 Nov 2019)");
  script_name("CentOS Update for kernel CESA-2019:3836 centos6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2019:3836");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-November/023512.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the CESA-2019:3836 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * hw: Machine Check Error on Page Size Change (IFU) (CVE-2018-12207)

  * hw: TSX Transaction Asynchronous Abort (TAA) (CVE-2019-11135)

  * Kernel: vhost_net: infinite loop while receiving packets leads to DoS
(CVE-2019-3900)

  * hw: Intel GPU Denial Of Service while accessing MMIO in lower power state
(CVE-2019-0154)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * [Intel 6.10 Bug] With mWait/C-states disabled, HT on, ibrs enabled,
performance impact observed on user space benchmark (BZ#1560787)

  * kernel-2.6.32-573.60.2.el6 hangs/resets during boot in
efi_enter_virtual_mode() on Xeon v2 E7-2870 (BZ#1645724)

  * Slab leak: skbuff_head_cache slab object still allocated after mcast
processes are stopped and 'fragments dropped after timeout' errors are
shown (BZ#1752536)
1646768 - CVE-2018-12207 hw: Machine Check Error on Page Size Change (IPU)
1698757 - CVE-2019-3900 Kernel: vhost_net: infinite loop while receiving packets leads to DoS
1724393 - CVE-2019-0154 hw: Intel GPU Denial Of Service while accessing MMIO in lower power state
1753062 - CVE-2019-11135 hw: TSX Transaction Asynchronous Abort (TAA)

6. Package List:

Red Hat Enterprise Linux Desktop (v. 6):

Source:
kernel-2.6.32-754.24.2.el6.src.rpm

i386:
kernel-2.6.32-754.24.2.el6.i686.rpm
kernel-debug-2.6.32-754.24.2.el6.i686.rpm
kernel-debug-debuginfo-2.6.32-754.24.2.el6.i686.rpm
kernel-debug-devel-2.6.32-754.24.2.el6.i686.rpm
kernel-debuginfo-2.6.32-754.24.2.el6.i686.rpm
kernel-debuginfo-common-i686-2.6.32-754.24.2.el6.i686.rpm
kernel-devel-2.6.32-754.24.2.el6.i686.rpm
kernel-headers-2.6.32-754.24.2.el6.i686.rpm
perf-2.6.32-754.24.2.el6.i686.rpm
perf-debuginfo-2.6.32-754.24.2.el6.i686.rpm
python-perf-debuginfo-2.6.32-754.24.2.el6.i686.rpm

noarch:
kernel-abi-whitelists-2.6.32-754.24.2.el6.noarch.rpm
kernel-doc-2.6.32-754.24.2.el6.noarch.rpm
kernel-firmware-2.6.32-754.24.2.el6.noarch.rpm

x86_64:
kernel-2.6.32-754.24.2.el6.x86_64.rpm
kernel-debug-2.6.32-754.24.2.el6.x86_64.rpm
kernel-debug-deb ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on CentOS 6.");

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

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~754.24.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~754.24.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~754.24.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~754.24.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~754.24.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~754.24.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~754.24.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~754.24.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~754.24.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~754.24.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
