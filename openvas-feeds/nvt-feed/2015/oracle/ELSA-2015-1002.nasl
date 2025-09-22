# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123115");
  script_cve_id("CVE-2015-3456");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:33 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-1002)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1002");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1002.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the ELSA-2015-1002 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.0.3-146.el5]
- xen-fdc-force-the-fifo-access-to-be-in-bounds-of-the-all.patch
- xen-FDC-Fix-buffer-overflow-Herv-Poussineau.patch
- Resolves: bz#1219333
 (xen: qemu: floppy disk controller flaw [rhel-5.11.z])

[3.0.3-144.el5]
- xm: Fix vcpu-pin complain for CPU number out of range (rhbz 955656)
- libxc: Support set affinity for more than 64 CPUS (rhbz 955656)
- libxc: Fixes for 'support affinity for more than 64 CPUS' (rhbz 955656)
- xend: Fix bug of a cpu affinity vcpu-pin under ia32pa (rhbz 955656)
- libxc: Fix cpu number overflow for vcpu-pin (rhbz 955656)

[3.0.3-143.el5]
- libxc: move error checking next to the function which returned the error (rhbz 870413)
- libxc: builder: limit maximum size of kernel/ramdisk (rhbz 870413)
- e1000: discard packets that are too long if !SBP and !LPE (rhbz 910844)
- e1000: discard oversized packets based on SBP<pipe>LPE (rhbz 910844)");

  script_tag(name:"affected", value:"'xen' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.3~146.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.0.3~146.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~146.el5_11", rls:"OracleLinux5"))) {
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
