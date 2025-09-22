# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122592");
  script_cve_id("CVE-2007-3919", "CVE-2007-5730", "CVE-2008-0928", "CVE-2008-1943", "CVE-2008-1944", "CVE-2008-2004");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:46 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-0194)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0194");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0194.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the ELSA-2008-0194 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.0.3-41.el5_1.5]
- Disable QEMU image format auto-detection CVE-2008-2004 (rhbz #444700)

[3.0.3-41.el5_1.4]
- Fix PVFB to validate frame buffer description (rhbz #443376)
- Fix PVFB to cope with bogus update requests (rhbz #368931)

[3.0.3-41.el5_1.3]
- Fix QEMU buffer overflow CVE-2007-5730 (rhbz #360381)
- Fix QEMU block device extents checking CVE-2008-0928 (rhbz #433560)

[3.0.3-41.el5_1.2]
- Fix FV O_DIRECT flushing (rhbz #435495)

[3.0.3-41.el5_1.1]
- Fixed xenbaked tmpfile flaw (CVE-2007-3919) (rhbz #350421)");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.3~41.el5_1.5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.0.3~41.el5_1.5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~41.el5_1.5", rls:"OracleLinux5"))) {
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
