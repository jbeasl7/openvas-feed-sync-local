# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122719");
  script_cve_id("CVE-2015-5279");
  script_tag(name:"creation_date", value:"2015-10-23 04:13:37 +0000 (Fri, 23 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-1925)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1925");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1925.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2015-1925 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-274.0.1.el5]
- Added kvm-add-oracle-workaround-for-libvirt-bug.patch
- Added kvm-Introduce-oel-machine-type.patch

[kvm-83.274.el5]
- net-add-checks-to-validate-ring-buffer-pointers.patch [bz#1263272]
- Resolves: bz#1263272
 (CVE-2015-5279 kvm: qemu: Heap overflow vulnerability in ne2000_receive() function [rhel-5.11.z])");

  script_tag(name:"affected", value:"'kvm' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~274.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~274.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~274.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~274.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~274.0.1.el5_11", rls:"OracleLinux5"))) {
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
