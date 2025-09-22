# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123614");
  script_cve_id("CVE-2013-2007");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:18 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0896)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0896");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0896.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2013-0896 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.12.1.2-2.355.el6_4.5]
- kvm-e1000-fix-link-down-handling-with-auto-negotiation.patch [bz#907716]
- kvm-e1000-unbreak-the-guest-network-when-migration-to-RH.patch [bz#907716]
- kvm-reimplement-error_setg-and-error_setg_errno-for-RHEL.patch [bz#957056]
- kvm-qga-set-umask-0077-when-daemonizing-CVE-2013-2007.patch [bz#957056]
- kvm-qga-distinguish-binary-modes-in-guest_file_open_mode.patch [bz#957056]
- kvm-qga-unlink-just-created-guest-file-if-fchmod-or-fdop.patch [bz#957056]
- Resolves: bz#907716
 (use set_link to change rtl8139 and e1000 network card's status but fail to make effectively after reboot guest)
- Resolves: bz#957056
 (CVE-2013-2007 qemu: guest agent creates files with insecure permissions in daemon mode [rhel-6.4.z])

[0.12.1.2-2.355.el6_4.4]
- kvm-virtio-balloon-fix-integer-overflow-in-BALLOON_CHANG.patch [bz#958750]
- Resolves: bz#958750
 (QMP event shows incorrect balloon value when balloon size is grater than or equal to 4G)");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.355.el6_4.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent-win32", rpm:"qemu-guest-agent-win32~0.12.1.2~2.355.el6_4.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.355.el6_4.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.355.el6_4.5", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.355.el6_4.5", rls:"OracleLinux6"))) {
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
