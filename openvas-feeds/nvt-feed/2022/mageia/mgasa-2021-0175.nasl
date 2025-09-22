# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0175");
  script_cve_id("CVE-2021-28688", "CVE-2021-28951", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-28972", "CVE-2021-29266");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-30 16:31:03 +0000 (Tue, 30 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0175)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0175");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0175.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28596");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28691");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.26");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.27");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-371.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2021-0175 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.10.27 and fixes at least
the following security issues:

The fix for XSA-365 includes initialization of pointers such that
subsequent cleanup code wouldn't use uninitialized or stale values.
This initialization went too far and may under certain conditions also
overwrite pointers which are in need of cleaning up. The lack of
cleanup would result in leaking persistent grants. The leak in turn
would prevent fully cleaning up after a respective guest has died,
leaving around zombie domains. A malicious or buggy frontend driver
may be able to cause resource leaks from the corresponding backend
driver. This can result in a host-wide Denial of Service (DoS).
(CVE-2021-28688 / XSA-371).

An issue was discovered in fs/io_uring.c in the Linux kernel through
5.11.8. It allows attackers to cause a denial of service (deadlock)
because exit may be waiting to park a SQPOLL thread, but concurrently
that SQPOLL thread is waiting for a signal to start (CVE-2021-28951).

A race condition was discovered in get_old_root in fs/btrfs/ctree.c in
the Linux kernel through 5.11.8. It allows attackers to cause a denial
of service (BUG) because of a lack of locking on an extent buffer
before a cloning operation (CVE-2021-28964).

In intel_pmu_drain_pebs_nhm in arch/x86/events/intel/ds.c in the Linux
kernel through 5.11.8 on some Haswell CPUs, userspace applications (such
as perf-fuzzer) can cause a system crash because the PEBS status in a
PEBS record is mishandled (CVE-2021-28971).

In drivers/pci/hotplug/rpadlpar_sysfs.c in the Linux kernel through 5.11.8,
the RPA PCI Hotplug driver has a user-tolerable buffer overflow when
writing a new device name to the driver from userspace, allowing userspace
to write data to the kernel stack frame directly. This occurs because
add_slot_store and remove_slot_store mishandle drc_name '\0' termination
(CVE-2021-28972).

An issue was discovered in the Linux kernel before 5.11.9. drivers/vhost/
vdpa.c has a use-after-free because v->config_ctx has an invalid value
upon re-opening a character device (CVE-2021-29266).

It also adds the following fixes:
- arm: enable OF_OVERLAY (mga#28596)

For other upstream fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.10.27-1.mga7", rpm:"kernel-linus-5.10.27-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.10.27~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.10.27-1.mga7", rpm:"kernel-linus-devel-5.10.27-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.10.27~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.10.27~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.10.27~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.10.27-1.mga7", rpm:"kernel-linus-source-5.10.27-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.10.27~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.10.27-1.mga8", rpm:"kernel-linus-5.10.27-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.10.27~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.10.27-1.mga8", rpm:"kernel-linus-devel-5.10.27-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.10.27~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.10.27~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.10.27~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.10.27-1.mga8", rpm:"kernel-linus-source-5.10.27-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.10.27~1.mga8", rls:"MAGEIA8"))) {
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
