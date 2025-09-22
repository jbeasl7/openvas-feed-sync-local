# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123841");
  script_cve_id("CVE-2012-2313");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:16 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-1174)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1174");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1174.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.13.1.el5, oracleasm-2.6.18-308.13.1.el5' package(s) announced via the ELSA-2012-1174 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-308.13.1.el5]
- [net] e1000e: Cleanup logic in e1000_check_for_serdes_link_82571 (Dean Nelson) [841370 771366]
- [net] e1000e: Correct link check logic for 82571 serdes (Dean Nelson) [841370 771366]
- [mm] NULL pointer dereference in __vm_enough_memory (Jerome Marchand) [840077 836244]
- [fs] dlm: fix slow rsb search in dir recovery (David Teigland) [838140 753244]
- [fs] autofs: propagate LOOKUP_DIRECTORY flag only for last comp (Ian Kent) [830264 814418]
- [fs] ext4: properly dirty split extent nodes (Eric Sandeen) [840946 839770]
- [scsi] don't offline devices with a reservation conflict (David Jeffery) [839196 835660]
- [fs] ext4: Fix overflow caused by missing cast in ext4_fallocate (Lukas Czerner) [837226 830351]
- [net] dl2k: Clean up rio_ioctl (Weiping Pan) [818822 818823] {CVE-2012-2313}
- [x86] sched: Avoid unnecessary overflow in sched_clock (Prarit Bhargava) [835450 834562]
- [net] tg3: Fix TSO handling (John Feeney) [833182 795672]
- [input] evdev: use after free from open/disconnect race (David Jeffery) [832448 822166]

[2.6.18-308.12.1.el5]
- [fs] nfs: Don't allow multiple mounts on same mntpnt with -o noac (Sachin Prabhu) [839806 839753]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.13.1.el5, oracleasm-2.6.18-308.13.1.el5' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.13.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.13.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.13.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.13.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.13.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.13.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.13.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.13.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.13.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.13.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.13.1.el5", rpm:"ocfs2-2.6.18-308.13.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.13.1.el5PAE", rpm:"ocfs2-2.6.18-308.13.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.13.1.el5debug", rpm:"ocfs2-2.6.18-308.13.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.13.1.el5xen", rpm:"ocfs2-2.6.18-308.13.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.13.1.el5", rpm:"oracleasm-2.6.18-308.13.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.13.1.el5PAE", rpm:"oracleasm-2.6.18-308.13.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.13.1.el5debug", rpm:"oracleasm-2.6.18-308.13.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.13.1.el5xen", rpm:"oracleasm-2.6.18-308.13.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
