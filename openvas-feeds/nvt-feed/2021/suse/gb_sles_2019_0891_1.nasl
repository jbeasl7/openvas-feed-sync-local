# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0891.1");
  script_cve_id("CVE-2019-6778", "CVE-2019-9824");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-22 15:15:38 +0000 (Fri, 22 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0891-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0891-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190891-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129623");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-April/005305.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2019:0891-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

Security issues fixed:

- Fixed an issue which could allow malicious PV guests may cause a host crash or
 gain access to data pertaining to other guests.Additionally, vulnerable configurations
 are likely to be unstable even in the absence of an attack (bsc#1126198).
- Fixed multiple access violations introduced by XENMEM_exchange hypercall which could allow
 a single PV guest to leak arbitrary amounts of memory, leading to a denial of service (bsc#1126192).
- Fixed an issue which could allow a malicious unprivileged guest userspace process to escalate its privilege
 to that of other userspace processes in the same guest and potentially thereby to that
 of the guest operating system (bsc#1126201).
- Fixed an issue which could allow malicious or buggy x86 PV guest kernels to mount a Denial of Service
 attack affecting the whole system (bsc#1126197).
- Fixed an issue which could allow an untrusted PV domain with access to a physical device to DMA into its own
 pagetables leading to privilege escalation (bsc#1126195).
- Fixed an issue which could allow a malicious or buggy x86 PV guest kernels can mount a Denial of Service
 attack affecting the whole system (bsc#1126196).
- CVE-2019-6778: Fixed a heap buffer overflow in tcp_emu() found in slirp (bsc#1123157).
- Fixed an issue which could allow malicious 64bit PV guests to cause a host crash (bsc#1127400).
- Fixed an issue which could allow malicious or buggy guests with passed through PCI devices to be able to
 escalate their privileges, crash the host, or access data belonging to other guests. Additionally memory
 leaks were also possible (bsc#1126140).
- Fixed a race condition issue which could allow malicious PV guests to escalate their privilege to that
 of the hypervisor (bsc#1126141).
- CVE-2019-9824: Fixed an information leak in SLiRP networking implementation which could allow a user/process
 to read uninitialised stack memory contents (bsc#1129623).

Other issues addressed:

- Upstream bug fixes (bsc#1027519)
- Packages should no longer use /var/adm/fillup-templates (bsc#1069468).
- Added Xen cmdline option 'suse_vtsc_tolerance' to avoid TSC emulation for HVM domUs (bsc#1026236).
- Fixed an issue where setup of grant_tables and other variables may fail (bsc#1126325).
- Fixed a building issue (bsc#1119161).
- Added a requirement for xen, xl.cfg firmware='pvgrub32<pipe>pvgrub64 (bsc#1127620).
- Fixed a segmetation fault in Libvirt when crash triggered on top of HVM guest (bsc#1120067).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.11.1_04~2.6.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.11.1_04~2.6.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.11.1_04~2.6.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.11.1_04~2.6.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.11.1_04~2.6.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.11.1_04~2.6.1", rls:"SLES12.0SP4"))) {
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
