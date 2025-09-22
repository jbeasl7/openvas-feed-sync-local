# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122101");
  script_cve_id("CVE-2011-1678", "CVE-2011-2522", "CVE-2011-2694", "CVE-2011-2724");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:05 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-1220)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1220");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1220.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba3x' package(s) announced via the ELSA-2011-1220 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.5.4-0.83.2]
- Security Release, add fix for CVE-2011-2724
- related: #722555

[3.5.4-0.83.1]
- Security Release, fixes CVE-2011-2694, CVE-2011-2522, CVE-2011-1678
- resolves: #722555");

  script_tag(name:"affected", value:"'samba3x' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"samba3x", rpm:"samba3x~3.5.4~0.83.el5_7.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-client", rpm:"samba3x-client~3.5.4~0.83.el5_7.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-common", rpm:"samba3x-common~3.5.4~0.83.el5_7.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-doc", rpm:"samba3x-doc~3.5.4~0.83.el5_7.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-domainjoin-gui", rpm:"samba3x-domainjoin-gui~3.5.4~0.83.el5_7.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-swat", rpm:"samba3x-swat~3.5.4~0.83.el5_7.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-winbind", rpm:"samba3x-winbind~3.5.4~0.83.el5_7.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-winbind-devel", rpm:"samba3x-winbind-devel~3.5.4~0.83.el5_7.2", rls:"OracleLinux5"))) {
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
