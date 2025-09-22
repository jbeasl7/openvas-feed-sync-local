# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122168");
  script_cve_id("CVE-2011-1750", "CVE-2011-1751");
  script_tag(name:"creation_date", value:"2015-10-06 11:14:10 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2011-0534)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0534");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0534.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2011-0534 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[qemu-kvm-0.12.1.2-2.160.el6]
- kvm-virtio-blk-fail-unaligned-requests.patch [bz#698910]
- kvm-Ignore-pci-unplug-requests-for-unpluggable-devices.patch [bz#699789]
- Resolves: bz#698910
 (CVE-2011-1750 virtio-blk: heap buffer overflow caused by unaligned requests [rhel-6.1])
- Resolves: bz#699789
 (CVE-2011-1751 acpi_piix4: missing hotplug check during device removal [rhel-6.1])

[qemu-kvm-0.12.1.2-2.159.el6]
- kvm-acpi_piix4-Maintain-RHEL6.0-migration.patch [bz#694095]
- Resolves: bz#694095
 (Migration fails when migrate guest from RHEL6.1 host to RHEL6 host with the same libvirt version)

[qemu-kvm-0.12.1.2-2.158.el6]
- kvm-bz-691704-vhost-skip-VGA-memory-regions.patch [bz#691704]
- kvm-ide-atapi-add-support-for-GET-EVENT-STATUS-NOTIFICAT.patch [bz#558256]
- kvm-atapi-Allow-GET_EVENT_STATUS_NOTIFICATION-after-medi.patch [bz#558256]
- kvm-atapi-Move-GET_EVENT_STATUS_NOTIFICATION-command-han.patch [bz#558256]
- kvm-atapi-GESN-Use-structs-for-commonly-used-field-types.patch [bz#558256]
- kvm-atapi-GESN-Standardise-event-response-handling-for-f.patch [bz#558256]
- kvm-atapi-GESN-implement-media-subcommand.patch [bz#558256]
- Resolves: bz#558256
 (rhel6 disk not detected first time in install)
- Resolves: bz#691704
 (Failed to boot up windows guest with huge memory and cpu and vhost=on within 30 mins)

[qemu-kvm-0.12.1.2-2.157.el6]
- kvm-qemu-img-rebase-Fix-read-only-new-backing-file.patch [bz#693741]
- kvm-floppy-save-and-restore-DIR-register.patch [bz#681777]
- kvm-block-Do-not-cache-device-size-for-removable-media.patch [bz#687900]
- kvm-cdrom-Allow-the-TEST_UNIT_READY-command-after-a-cdro.patch [bz#683877]
- kvm-cdrom-Make-disc-change-event-visible-to-guests.patch [bz#683877]
- Resolves: bz#681777
 (floppy I/O error after live migration while floppy in use)
- Resolves: bz#683877
 (RHEL6 guests fail to update cdrom block size on media change)
- Resolves: bz#687900
 (qemu host cdrom support not properly updating guests on media changes at physical CD/DVD drives)
- Resolves: bz#693741
 (qemu-img re-base fail with read-only new backing file)

[qemu-kvm-0.12.1.2-2.156.el6]
- kvm-Revert-net-socket-allow-ipv6-for-net_socket_listen_i.patch [bz#680356]
- kvm-Revert-Use-getaddrinfo-for-migration.patch [bz#680356]
- Related: bz#680356
 (Live migration failed in ipv6 environment)
- Fixes bz#694196
 (RHEL 6.1 qemu-kvm: Specifying ipv6 addresses breaks migration)

[qemu-kvm-0.12.1.2-2.155.el6]
- kvm-configure-fix-out-of-tree-build-with-enable-spice.patch [bz#641833]
- kvm-ccid-card-emulated-replace-DEFINE_PROP_ENUM-with-DEF.patch [bz#641833]
- kvm-Revert-qdev-properties-add-PROP_TYPE_ENUM.patch [bz#641833]
- kvm-Revert-qdev-add-data-pointer-to-Property.patch [bz#641833]
- kvm-Revert-qdev-add-print_options-callback.patch [bz#641833]
- kvm-ccid-v18_upstream-v25-cleanup.patch [bz#641833]
- kvm-libcacard-vscard_common.h-upstream-v18-v25-diff.patch [bz#641833]
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.160.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.160.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.160.el6", rls:"OracleLinux6"))) {
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
