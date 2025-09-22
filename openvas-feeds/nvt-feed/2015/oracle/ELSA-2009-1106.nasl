# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122474");
  script_cve_id("CVE-2009-1072", "CVE-2009-1192", "CVE-2009-1439", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1758", "CVE-2009-3238");
  script_tag(name:"creation_date", value:"2015-10-08 11:46:10 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 03:30:15 +0000 (Thu, 15 Feb 2024)");

  script_name("Oracle: Security Advisory (ELSA-2009-1106)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1106");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1106.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-128.1.14.0.1.el5, oracleasm-2.6.18-128.1.14.0.1.el5' package(s) announced via the ELSA-2009-1106 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-128.1.14.0.1.el5]
- [NET] Add entropy support to e1000 and bnx2 (John Sobecki,Guru Anbalagane) [orabug 6045759]
- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]
- [nfs] convert ENETUNREACH to ENOTCONN (Guru Anbalagane) [orabug 7689332]
- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]
- [MM] balloon code needs to adjust totalhigh_pages (Chuck Anderson) [orabug 8300888]

[2.6.18-128.1.14.el5]
- [nfs] v4: client handling of MAY_EXEC in nfs_permission (Peter Staubach ) [500301 500302] {CVE-2009-1630}
- [fs] proc: avoid info leaks to non-privileged processes (Amerigo Wang ) [499546 499541]
- [net] tg3: Fix firmware event timeouts (Jiri Pirko ) [502837 481715]
- [scsi] libiscsi: fix nop response/reply and session cleanup race (Jiri Pirko ) [502916 497411]
- [fs] cifs: fix pointer and checks in cifs_follow_symlink (Jeff Layton ) [496576 496577] {CVE-2009-1633}
- [fs] cifs: fix error handling in parse_DFS_referrals (Jeff Layton ) [496576 496577] {CVE-2009-1633}
- [fs] cifs: buffer overruns when converting strings (Jeff Layton ) [496576 496577] {CVE-2009-1633}
- [fs] cifs: unicode alignment and buffer sizing problems (Jeff Layton ) [494279 494280] {CVE-2009-1439}
- [x86] xen: fix local denial of service (Chris Lalancette ) [500950 500951] {CVE-2009-1758}
- [misc] compile: add -fwrapv to gcc CFLAGS (Don Zickus ) [501751 491266]
- [misc] random: make get_random_int more random (Amerigo Wang ) [499783 499776]
- [gfs2] fix uninterruptible quotad sleeping (Steven Whitehouse ) [501742 492943]
- [mm] cow vs gup race fix (Andrea Arcangeli ) [486921 471613]
- [mm] fork vs gup race fix (Andrea Arcangeli ) [486921 471613]
- [nfs] fix hangs during heavy write workloads (Peter Staubach ) [486926 469848]

[2.6.18-128.1.13.el5]
- [misc] add some long-missing capabilities to CAP_FS_MASK (Eric Paris ) [499075 497271 499076 497272] {CVE-2009-1072}
- [agp] zero pages before sending to userspace (Jiri Olsa ) [497025 497026] {CVE-2009-1192}
- [fs] keep eventpoll from locking up the box (Josef Bacik ) [497322 487585]
- [misc] waitpid reports stopped process more than once (Vitaly Mayatskikh ) [486945 481199]
- [ata] libata: ahci enclosure management bios workaround (David Milburn ) [500120 488471]

[2.6.18-128.1.12.el5]
- [ia64] fix regression in nanosleep syscall (Prarit Bhargava ) [500349 499289]

[2.6.18-128.1.11.el5]
- [nfs] race with nfs_access_cache_shrinker() and umount (Peter Staubach ) [498653 469225]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-128.1.14.0.1.el5, oracleasm-2.6.18-128.1.14.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.1.14.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.1.14.0.1.el5", rpm:"ocfs2-2.6.18-128.1.14.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.1.14.0.1.el5PAE", rpm:"ocfs2-2.6.18-128.1.14.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.1.14.0.1.el5debug", rpm:"ocfs2-2.6.18-128.1.14.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.1.14.0.1.el5xen", rpm:"ocfs2-2.6.18-128.1.14.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.1.14.0.1.el5", rpm:"oracleasm-2.6.18-128.1.14.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.1.14.0.1.el5PAE", rpm:"oracleasm-2.6.18-128.1.14.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.1.14.0.1.el5debug", rpm:"oracleasm-2.6.18-128.1.14.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.1.14.0.1.el5xen", rpm:"oracleasm-2.6.18-128.1.14.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
