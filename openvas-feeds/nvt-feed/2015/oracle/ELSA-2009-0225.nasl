# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122525");
  script_cve_id("CVE-2008-5029", "CVE-2008-5079", "CVE-2008-5182", "CVE-2008-5300");
  script_tag(name:"creation_date", value:"2015-10-08 11:47:17 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-0225)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-0225");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-0225.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-128.el5, oracleasm-2.6.18-128.el5' package(s) announced via the ELSA-2009-0225 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-128.el5]
- [cifs] cifs_writepages may skip unwritten pages (Jeff Layton ) [470267]

[2.6.18-127.el5]
- Revert: [i386]: check for dmi_data in powernow_k8 driver (Prarit Bhargava ) [476184]
- [xen] re-enable using xenpv in boot path for FV guests (Don Dutile ) [473899]
- [xen] pv_hvm: guest hang on FV save/restore (Don Dutile ) [475778]
- [openib] fix ipoib oops in unicast_arp_send (Doug Ledford ) [476005]
- [scsi] fnic: remove link down count processing (mchristi@redhat.com ) [474935]
- Revert: [x86] disable hpet on machine_crash_shutdown (Neil Horman ) [475652]
- [scsi] ibmvscsi: EH fails due to insufficient resources (AMEET M. PARANJAPE ) [475618]
- [x86_64] proc: export GART region through /proc/iomem (Neil Horman ) [475507]
- [acpi] add xw8600 and xw6600 to GPE0 block blacklist (Prarit Bhargava ) [475418]
- [net] cxgb3: fixup embedded firmware problems take 2 (Andy Gospodarek ) [469774]

[2.6.18-126.el5]
- [scsi] mpt fusion: disable msi by default (Tomas Henzl ) [474465]
- [scsi] fcoe: update drivers (mchristi@redhat.com ) [474089]
- [scsi] fix error handler to call scsi_decide_disposition (Tom Coughlan ) [474345]
- [scsi] lpfc: fix cancel_retry_delay (Tom Coughlan ) [470610]
- [x86] disable hpet on machine_crash_shutdown (Neil Horman ) [473038]
- Revert [mm] keep pagefault from happening under pagelock (Don Zickus ) [473150]
- [net] enic: update to version 1.0.0.648 (Andy Gospodarek ) [473871]
- [scsi] qla4xxx: increase iscsi session check to 3-tuple (Marcus Barrow ) [474736]
- [agp] update the names of some graphics drivers (John Villalovos ) [472438]
- [net] atm: prevent local denial of service (Eugene Teo ) [473701] {CVE-2008-5079}
- [scsi] remove scsi_dh_alua (mchristi@redhat.com ) [471920]
- [scsi] qla2xx/qla84xx: occasional panic on loading (Marcus Barrow ) [472382]
- [net] cxgb3: eeh and eeprom fixups (Andy Gospodarek ) [441959]
- [net] cxgb3: fixup embedded firmware problems (Andy Gospodarek ) [469774]
- [wireless] iwlwifi/mac80211: various small fixes (John W. Linville ) [468967]
- [x86_64] fix AMD IOMMU boot issue (Joachim Deguara ) [473464]
- [x86_64] limit num of mce sysfs files removed on suspend (Prarit Bhargava ) [467725]
- [xen] console: make LUKS passphrase readable (Bill Burns ) [466240]
- [x86_64] Calgary IOMMU sysdata fixes (Prarit Bhargava ) [474047]
- [alsa] select 3stack-dig model for SC CELSIUS R670 (Jaroslav Kysela ) [470449]
- [ata] libata: lba_28_ok sector off by one (David Milburn ) [464868]
- [ppc64] fix system calls on Cell entered with XER.SO=1 (Jesse Larrew ) [474196]
- [block] fix max_segment_size, seg_boundary mask setting (Milan Broz ) [471639]
- [fs] jbd: alter EIO test to avoid spurious jbd aborts (Eric Sandeen ) [472276]
- [acpi] acpi_cpufreq: fix panic when removing module (Prarit Bhargava ) [472844]
- [openib] ehca: fix generating flush work completions (AMEET M. PARANJAPE ) [472812]
- [ata] libata: sata_nv hard reset ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-128.el5, oracleasm-2.6.18-128.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.el5", rpm:"ocfs2-2.6.18-128.el5~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.el5PAE", rpm:"ocfs2-2.6.18-128.el5PAE~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.el5debug", rpm:"ocfs2-2.6.18-128.el5debug~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-128.el5xen", rpm:"ocfs2-2.6.18-128.el5xen~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.el5", rpm:"oracleasm-2.6.18-128.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.el5PAE", rpm:"oracleasm-2.6.18-128.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.el5debug", rpm:"oracleasm-2.6.18-128.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-128.el5xen", rpm:"oracleasm-2.6.18-128.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
