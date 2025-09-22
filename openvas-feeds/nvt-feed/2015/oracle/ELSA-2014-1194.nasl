# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123308");
  script_cve_id("CVE-2012-5485", "CVE-2012-5486", "CVE-2012-5488", "CVE-2012-5497", "CVE-2012-5498", "CVE-2012-5499", "CVE-2012-5500", "CVE-2013-6496", "CVE-2014-3521");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:04 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1194)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1194");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1194.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'conga' package(s) announced via the ELSA-2014-1194 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.12.2-81.0.2.el5]
- Replaced redhat logo image in Data.fs

[0.12.2-81.0.1.el5]
- Added conga-enterprise-Carthage.patch to support OEL5
- Replaced redhat logo image in conga-0.12.2.tar.gz

[0.12.2-81]
- luci: prevent non-admin user from unauthorized executive access
 Resolves: rhbz#1089310

[0.12.2-79]
- luci: drop unsuccessful monkey patch application wrt. Plone 20121106 advisory
 Related: rhbz#956861

[0.12.2-78]
- luci: reflect startup_wait parameter added in postgres-8 RA
 Resolves: rhbz#1065263
- luci: Multiple information leak flaws in various luci site extensions
 Resolves: rhbz#1076148

[0.12.2-72]
- luci: fix mishandling of distro release string
 Resolves: rhbz#1072075
- luci: fix initscript does not check return values correctly
 Resolves: rhbz#970288
- ricci: fix end-use modules do not handle stdin polling correctly
 Resolves: rhbz#1076711

[0.12.2-69]
- luci: apply relevant parts of Plone 20121106 advisory (multiple vectors)
 Resolves: rhbz#956861");

  script_tag(name:"affected", value:"'conga' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"conga", rpm:"conga~0.12.2~81.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luci", rpm:"luci~0.12.2~81.0.2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ricci", rpm:"ricci~0.12.2~81.0.2.el5", rls:"OracleLinux5"))) {
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
