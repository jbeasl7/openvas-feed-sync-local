# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4031.1");
  script_cve_id("CVE-2020-36766", "CVE-2023-0394", "CVE-2023-1192", "CVE-2023-1206", "CVE-2023-1859", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39194", "CVE-2023-42754", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-4881", "CVE-2023-4921");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 19:38:11 +0000 (Thu, 14 Sep 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4031-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234031-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215954");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-October/016617.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:4031-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2023-39192: Fixed an out of bounds read in the netfilter (bsc#1215858).
- CVE-2023-39193: Fixed an out of bounds read in the xtables subsystem (bsc#1215860).
- CVE-2023-39194: Fixed an out of bounds read in the XFRM subsystem (bsc#1215861).
- CVE-2023-42754: Fixed a NULL pointer dereference in the IPv4 stack that could lead to denial of service (bsc#1215467).
- CVE-2023-1206: Fixed a hash collision flaw in the IPv6 connection lookup table which could be exploited by network adjacent attackers, increasing CPU usage by 95% (bsc#1212703).
- CVE-2023-4921: Fixed a use-after-free vulnerability in the QFQ network scheduler which could be exploited to achieve local privilege escalation (bsc#1215275).
- CVE-2023-0394: Fixed a NULL pointer dereference in the IPv6 stack that could lead to denial of service (bsc#1207168).
- CVE-2023-4622: Fixed a use-after-free vulnerability in the Unix domain sockets component which could be exploited to achieve local privilege escalation (bsc#1215117).
- CVE-2023-4623: Fixed a use-after-free issue in the HFSC network scheduler which could be exploited to achieve local privilege escalation (bsc#1215115).
- CVE-2020-36766: Fixed a potential information leak in in the CEC driver (bsc#1215299).
- CVE-2023-1859: Fixed a use-after-free flaw in Xen transport for 9pfs which could be exploited to crash the system (bsc#1210169).
- CVE-2023-4881: Fixed a out-of-bounds write flaw in the netfilter subsystem that could lead to potential information disclosure or a denial of service (bsc#1215221).
- CVE-2023-1192: Fixed use-after-free in cifs_demultiplex_thread() (bsc#1208995).

The following non-security bugs were fixed:

- 9p/trans_virtio: Remove sysfs file on probe failure (git-fixes).
- Drivers: hv: vmbus: Do not dereference ACPI root object handle (git-fixes).
- Input: psmouse - fix OOB access in Elantech protocol (git-fixes).
- Input: raspberrypi-ts - fix refcount leak in rpi_ts_probe (git-fixes).
- Input: xpad - add constants for GIP interface numbers (git-fixes).
- Input: xpad - delete a Razer DeathAdder mouse VID/PID entry (git-fixes).
- KVM: s390: vsie: Fix the initialization of the epoch extension (epdx) field (git-fixes bsc#1215897).
- KVM: s390: vsie: fix the length of APCB bitmap (git-fixes bsc#1215898).
- NFS/pNFS: Report EINVAL errors from connect() to the server (git-fixes).
- NFSv4/pnfs: minor fix for cleanup path in nfs4_get_device_info (git-fixes).
- README: update rebuilding information (jsc#PED-5021).
- USB: serial: option: add FOXCONN T99W368/T99W373 product (git-fixes).
- USB: serial: option: add Quectel EM05G variant (0x030e) (git-fixes).
- VSOCK: handle VIRTIO_VSOCK_OP_CREDIT_REQUEST (git-fixes).
- arm64: insn: Fix ldadd instruction encoding (git-fixes)
- arm64: kgdb: Set PSTATE.SS to 1 to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.179.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.179.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.179.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.179.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.179.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.179.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.179.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.179.1", rls:"SLES12.0SP5"))) {
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
