# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122938");
  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2115", "CVE-2016-2118");
  script_tag(name:"creation_date", value:"2016-05-09 11:24:54 +0000 (Mon, 09 May 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 17:17:00 +0000 (Fri, 27 Sep 2019)");

  script_name("Oracle: Security Advisory (ELSA-2016-0613)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0613");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0613.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba3x' package(s) announced via the ELSA-2016-0613 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.6.23-12.0.1]
- Remove use-after-free talloc_tos() inlined function problem (John Haxby) [orabug 19973497]

[3.6.23-12]
- related: #1322685 - Update CVE patchset

[3.6.23-11]
- related: #1322685 - Update CVE patchset

[3.6.23-10]
- resolves: #1322685 - Fix CVE-2015-5370
- resolves: #1322685 - Fix CVE-2016-2110
- resolves: #1322685 - Fix CVE-2016-2111
- resolves: #1322685 - Fix CVE-2016-2112
- resolves: #1322685 - Fix CVE-2016-2115
- resolves: #1322685 - Fix CVE-2016-2118 (Known as Badlock)");

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

  if(!isnull(res = isrpmvuln(pkg:"samba3x", rpm:"samba3x~3.6.23~12.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-client", rpm:"samba3x-client~3.6.23~12.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-common", rpm:"samba3x-common~3.6.23~12.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-doc", rpm:"samba3x-doc~3.6.23~12.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-domainjoin-gui", rpm:"samba3x-domainjoin-gui~3.6.23~12.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-swat", rpm:"samba3x-swat~3.6.23~12.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-winbind", rpm:"samba3x-winbind~3.6.23~12.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba3x-winbind-devel", rpm:"samba3x-winbind-devel~3.6.23~12.0.1.el5_11", rls:"OracleLinux5"))) {
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
