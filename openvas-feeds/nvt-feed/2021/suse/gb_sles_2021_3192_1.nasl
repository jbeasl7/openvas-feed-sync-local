# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3192.1");
  script_cve_id("CVE-2018-9517", "CVE-2019-3874", "CVE-2019-3900", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3679", "CVE-2021-3732", "CVE-2021-3753", "CVE-2021-3759", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38204");
  script_tag(name:"creation_date", value:"2021-09-23 07:04:43 +0000 (Thu, 23 Sep 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 18:55:35 +0000 (Thu, 10 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3192-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3192-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213192-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190117");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-September/009486.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3192-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2018-9517: Fixed possible memory corruption due to a use after free in pppol2tp_connect (bsc#1108488).
- CVE-2019-3874: Fixed possible denial of service attack via SCTP socket buffer used by a userspace applications (bnc#1129898).
- CVE-2019-3900: Fixed an infinite loop issue while handling incoming packets in handle_rx() (bnc#1133374).
- CVE-2021-3640: Fixed a Use-After-Free vulnerability in function sco_sock_sendmsg() in the bluetooth stack (bsc#1188172).
- CVE-2021-3653: Missing validation of the `int_ctl` VMCB field and allows a malicious L1 guest to enable AVIC support for the L2 guest. (bsc#1189399).
- CVE-2021-3656: Missing validation of the `virt_ext` VMCB field and allows a malicious L1 guest to disable both VMLOAD/VMSAVE intercepts and VLS for the L2 guest (bsc#1189400).
- CVE-2021-3679: A lack of CPU resource in tracing module functionality was found in the way user uses trace ring buffer in a specific way. Only privileged local users (with CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service (bnc#1189057).
- CVE-2021-3732: Mounting overlayfs inside an unprivileged user namespace can reveal files (bsc#1189706).
- CVE-2021-3753: Fixed race out-of-bounds in virtual terminal handling (bsc#1190025).
- CVE-2021-3759: Unaccounted ipc objects in Linux kernel could have lead to breaking memcg limits and DoS attacks (bsc#1190115).
- CVE-2021-38160: Data corruption or loss could be triggered by an untrusted device that supplies a buf->len value exceeding the buffer size in drivers/char/virtio_console.c (bsc#1190117)
- CVE-2021-38198: arch/x86/kvm/mmu/paging_tmpl.h incorrectly computes the access permissions of a shadow page, leading to a missing guest protection page fault (bnc#1189262).
- CVE-2021-38204: drivers/usb/host/max3421-hcd.c allowed physically proximate attackers to cause a denial of service (use-after-free and panic) by removing a MAX-3421 USB device in certain situations (bnc#1189291).

The following non-security bugs were fixed:

- ACPI: NFIT: Fix support for virtual SPA ranges (git-fixes).
- ALSA: seq: Fix racy deletion of subscriber (git-fixes).
- ASoC: cs42l42: Do not allow SND_SOC_DAIFMT_LEFT_J (git-fixes).
- ASoC: cs42l42: Fix inversion of ADC Notch Switch control (git-fixes).
- ASoC: cs42l42: Remove duplicate control for WNF filter frequency (git-fixes).
- Bluetooth: Move shutdown callback before flushing tx and rx queue (git-fixes).
- Bluetooth: add timeout sanity check to hci_inquiry (git-fixes).
- Bluetooth: fix repeated calls to sco_sock_kill (git-fixes).
- Bluetooth: increase BTNAMSIZ to 21 chars to fix potential buffer overflow (git-fixes).
- Bluetooth: sco: prevent information leak in sco_conn_defer_accept() (git-fixes).
- KVM: SVM: Call SEV Guest ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.73.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.73.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.73.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.73.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.73.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.73.1", rls:"SLES12.0SP5"))) {
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
