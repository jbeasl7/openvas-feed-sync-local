# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123130");
  script_cve_id("CVE-2014-8106");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:44 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-0867)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0867");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0867.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2015-0867 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.12.1.2-2.448.el6_6.2]
- kvm-cirrus-fix-blit-region-check.patch [bz#1170571]
- kvm-cirrus-don-t-overflow-CirrusVGAState-cirrus_bltbuf.patch [bz#1170571]
- Resolves: bz#1170571
 (CVE-2014-8106 qemu-kvm: qemu: cirrus: insufficient blit region checks [rhel-6.6.z])

[0.12.1.2-2.448.el6_6.1]
- kvm-net-Forbid-dealing-with-packets-when-VM-is-not-run_2.patch [bz#970103]
- kvm-virtio-net-drop-assert-on-vm-stop.patch [bz#970103]
- kvm-migration-set-speed-to-maximum-during-last-stage_2.patch [bz#970103]
- kvm-migration-only-call-append-when-there-is-something_2.patch [bz#970103]
- kvm-migration-Only-call-memmove-when-there-is-anything-t.patch [bz#970103]
- kvm-migration-remove-not-needed-ram_save_remaining-fun_2.patch [bz#970103]
- kvm-migration-move-bandwidth-calculation-to-inside-sta_2.patch [bz#970103]
- kvm-migration-Don-t-calculate-bandwidth-when-last-cycl_2.patch [bz#970103]
- kvm-buffered_flush-return-errors.patch [bz#970103]
- kvm-bandwidth_limit-standarize-in-size_t.patch [bz#970103]
- kvm-fix-bz-1196970.patch [bz#1196970]
- Resolves: bz#1196970
 (Migrate status is failed after migrate_cancel.)
- Resolves: bz#970103
 (Downtime during live migration of busy VM is much higher than migration_downtime in vdsm.conf)");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.448.el6_6.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.448.el6_6.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.448.el6_6.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.448.el6_6.2", rls:"OracleLinux6"))) {
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
