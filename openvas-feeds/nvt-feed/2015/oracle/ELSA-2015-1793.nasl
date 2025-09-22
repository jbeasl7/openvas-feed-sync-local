# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123006");
  script_cve_id("CVE-2015-5165");
  script_tag(name:"creation_date", value:"2015-10-06 10:49:57 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-1793)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1793");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1793.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2015-1793 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.5.3-86.el7_1.6]
- kvm-rtl8139-avoid-nested-ifs-in-IP-header-parsing-CVE-20.patch [bz#1248764]
- kvm-rtl8139-drop-tautologous-if-ip-.-statement-CVE-2015-.patch [bz#1248764]
- kvm-rtl8139-skip-offload-on-short-Ethernet-IP-header-CVE.patch [bz#1248764]
- kvm-rtl8139-check-IP-Header-Length-field-CVE-2015-5165.patch [bz#1248764]
- kvm-rtl8139-check-IP-Total-Length-field-CVE-2015-5165.patch [bz#1248764]
- kvm-rtl8139-skip-offload-on-short-TCP-header-CVE-2015-51.patch [bz#1248764]
- kvm-rtl8139-check-TCP-Data-Offset-field-CVE-2015-5165.patch [bz#1248764]
- Resolves: bz#1248764
 (CVE-2015-5165 qemu-kvm: Qemu: rtl8139 uninitialized heap memory information leakage to guest [rhel-7.1.z])");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~86.el7_1.6", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~86.el7_1.6", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~86.el7_1.6", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~86.el7_1.6", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~86.el7_1.6", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~86.el7_1.6", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~86.el7_1.6", rls:"OracleLinux7"))) {
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
