# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123246");
  script_cve_id("CVE-2014-3633", "CVE-2014-3657", "CVE-2014-7823");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:13 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1873)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1873");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1873.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the ELSA-2014-1873 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.10.2-46.0.1.el6_6.2]
- Replace docs/et.png in tarball with blank image

[0.10.2-46.el6_6.2]
- qemu: allow restore with non-migratable XML input (rhbz#1155564)
- qemu: Introduce qemuDomainDefCheckABIStability (rhbz#1155564)
- Make ABI stability issue easier to debug (rhbz#1155564)
- CVE-2014-3633: qemu: blkiotune: Use correct definition when looking up disk (CVE-2014-3633)
- domain_conf: fix domain deadlock (CVE-2014-3657)
- CVE-2014-7823: dumpxml: security hole with migratable flag (CVE-2014-7823)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~46.0.1.el6_6.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~46.0.1.el6_6.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~46.0.1.el6_6.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.10.2~46.0.1.el6_6.2", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~46.0.1.el6_6.2", rls:"OracleLinux6"))) {
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
