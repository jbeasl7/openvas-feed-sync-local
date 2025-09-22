# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123746");
  script_cve_id("CVE-2012-1568", "CVE-2012-4444", "CVE-2012-5515");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:00 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2013-0168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0168");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0168.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-348.1.1.el5, oracleasm-2.6.18-348.1.1.el5' package(s) announced via the ELSA-2013-0168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-348.1.1]
- [pci] intel-iommu: reduce max num of domains supported (Don Dutile) [886876 885125]
- [fs] gfs2: Fix leak of cached directory hash table (Steven Whitehouse) [886124 831330]
- [x86] mm: randomize SHLIB_BASE (Petr Matousek) [804953 804954] {CVE-2012-1568}
- [net] be2net: create RSS rings even in multi-channel configs (Ivan Vecera) [884702 878209]
- [net] tg3: Avoid dma read error (John Feeney) [885692 877474]
- [misc] Fix unsupported hardware message (Prarit Bhargava) [885063 876587]
- [net] ipv6: discard overlapping fragment (Jiri Pirko) [874837 874838] {CVE-2012-4444}
- [usb] Fix serial port reference counting on hotplug remove (Don Zickus) [885700 845447]
- [net] bridge: export its presence and fix bonding igmp reporting (Veaceslav Falico) [884742 843473]
- [fs] nfs: move wait for server->active from put_super to kill_sb (Jeff Layton) [884708 839839]
- [scsi] libfc: fix indefinite rport restart (Neil Horman) [884740 595184]
- [scsi] libfc: Retry a rejected PRLI request (Neil Horman) [884740 595184]
- [scsi] libfc: Fix remote port restart problem (Neil Horman) [884740 595184]
- [xen] memop: limit guest specified extent order (Laszlo Ersek) [878449 878450] {CVE-2012-5515}
- [xen] get bottom of EBDA from the multiboot data structure (Paolo Bonzini) [885062 881885]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-348.1.1.el5, oracleasm-2.6.18-348.1.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.1.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.1.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.1.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.1.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.1.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.1.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.1.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.1.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.1.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.1.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.1.1.el5", rpm:"ocfs2-2.6.18-348.1.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.1.1.el5PAE", rpm:"ocfs2-2.6.18-348.1.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.1.1.el5debug", rpm:"ocfs2-2.6.18-348.1.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.1.1.el5xen", rpm:"ocfs2-2.6.18-348.1.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.1.1.el5", rpm:"oracleasm-2.6.18-348.1.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.1.1.el5PAE", rpm:"oracleasm-2.6.18-348.1.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.1.1.el5debug", rpm:"oracleasm-2.6.18-348.1.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.1.1.el5xen", rpm:"oracleasm-2.6.18-348.1.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
