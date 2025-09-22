# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122038");
  script_cve_id("CVE-2011-2527");
  script_tag(name:"creation_date", value:"2015-10-06 11:12:03 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2011-1531)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1531");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1531.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2011-1531 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[qemu-kvm-0.12.1.2-2.209.el6]
- kvm-hda-do-not-mix-output-and-input-streams-RHBZ-740493-v2.patch [bz#740493]
- kvm-hda-do-not-mix-output-and-input-stream-states-RHBZ-740493-v2.patch [bz#740493]
- kvm-intel-hda-fix-stream-search.patch [bz#740493]
- Resolves: bz#740493
 (audio playing doesn't work when sound recorder is opened)

[qemu-kvm-0.12.1.2-2.208.el6]
- kvm-migration-flush-migration-data-to-disk.patch [bz#721114]
- Resolves: bz#721114
 (qemu fails to restore guests that were previously suspended on host shutdown)

[qemu-kvm-0.12.1.2-2.207.el6]
- kvm-migration-s-dprintf-DPRINTF-v2.patch [bz#669581]
- kvm-migration-simplify-state-assignmente-v2.patch [bz#669581]
- vm-migration-Check-that-migration-is-active-before-canc-v2.patch [bz#669581]
- kvm-Reorganize-and-fix-monitor-resume-after-migration-v2.patch [bz#669581]
- kvm-migration-add-error-handling-to-migrate_fd_put_notif-v2.patch [bz#669581]
- kvm-migration-If-there-is-one-error-it-makes-no-sense-to-v2.patch [bz#669581]
- kvm-buffered_file-Use-right-opaque-v2.patch [bz#669581]
- kvm-buffered_file-reuse-QEMUFile-has_error-field-v2.patch [bz#669581]
- kvm-migration-don-t-write-when-migration-is-not-active-v2.patch [bz#669581]
- kvm-migration-set-error-if-select-return-one-error-v2.patch [bz#669581]
- kvm-migration-change-has_error-to-contain-errno-values-v2.patch [bz#669581]
- kvm-migration-return-real-error-code-v2.patch [bz#669581]
- kvm-migration-rename-qemu_file_has_error-to-qemu_file_ge-v2.patch [bz#669581]
- kvm-savevm-Rename-has_error-to-last_error-field-v2.patch [bz#669581]
- kvm-migration-use-qemu_file_get_error-return-value-when--v2.patch [bz#669581]
- kvm-migration-make-save_live-return-errors-v2.patch [bz#669581]
- kvm-savevm-qemu_fille_buffer-used-to-return-one-error-fo-v2.patch [bz#669581]
- kvm-Fix-segfault-on-migration-completion.patch [bz#669581 bz#749806]
- Resolves: bz#669581
 (Migration Never end while Use firewall reject migration tcp port)
- Resolves: bz#749806
 (Migration segfault on migrate_fd_put_notify()/qemu_file_get_error())

[qemu-kvm-0.12.1.2-2.206.el6]
- kvm-Revert-savevm-qemu_fille_buffer-used-to-return-one-e.patch [bz#669581]
- kvm-Revert-migration-make-save_live-return-errors.patch [bz#669581]
- kvm-Revert-migration-use-qemu_file_get_error-return-valu.patch [bz#669581]
- kvm-Revert-savevm-Rename-has_error-to-last_error-field.patch [bz#669581]
- kvm-Revert-migration-rename-qemu_file_has_error-to-qemu_.patch [bz#669581]
- kvm-Revert-migration-return-real-error-code.patch [bz#669581]
- kvm-Revert-migration-change-has_error-to-contain-errno-v.patch [bz#669581]
- kvm-Revert-migration-set-error-if-select-return-one-erro.patch [bz#669581]
- kvm-Revert-migration-don-t-write-when-migration-is-not-a.patch [bz#669581]
- kvm-Revert-buffered_file-reuse-QEMUFile-has_error-field.patch [bz#669581]
- kvm-Revert-buffered_file-Use-right-opaque.patch [bz#669581]
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

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.209.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.209.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.209.el6", rls:"OracleLinux6"))) {
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
