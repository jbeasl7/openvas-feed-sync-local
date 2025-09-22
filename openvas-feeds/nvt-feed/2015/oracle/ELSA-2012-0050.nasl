# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122009");
  script_cve_id("CVE-2012-0029");
  script_tag(name:"creation_date", value:"2015-10-06 11:11:37 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-0050)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0050");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0050.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2012-0050 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[qemu-kvm-0.12.1.2-2.209.el6_2.4]
- kvm-e1000-prevent-buffer-overflow-when-processing-legacy.patch [bz#772081]
- Resolves: bz#772081
 (EMBARGOED CVE-2012-0029 qemu-kvm: e1000: process_tx_desc legacy mode packets heap overflow [rhel-6.2.z])

[qemu-kvm-0.12.1.2-2.209.el6_2.3]
- kvm-Revert-virtio-blk-refuse-SG_IO-requests-with-scsi-of.patch [for bz#767721]
- kvm-virtio-blk-refuse-SG_IO-requests-with-scsi-off-v2.patch [bz#767721]
- CVE: CVE-2011-4127
- Resolves: bz#767721
 (qemu-kvm: virtio-blk: refuse SG_IO requests with scsi=off (CVE-2011-4127 mitigation) [rhel-6.2.z])

[qemu-kvm-0.12.1.2-2.209.el6_2.2]
- kvm-virtio-blk-refuse-SG_IO-requests-with-scsi-off.patch [bz#752375]
- CVE: CVE-2011-4127
- Resolves: bz#767721
 (EMBARGOED qemu-kvm: virtio-blk: refuse SG_IO requests with scsi=off (CVE-2011-4127 mitigation) [rhel-6.3])
- Resolves: bz#767906
 (qemu-kvm should be built with full relro and PIE support)");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.209.el6_2.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.209.el6_2.4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.209.el6_2.4", rls:"OracleLinux6"))) {
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
