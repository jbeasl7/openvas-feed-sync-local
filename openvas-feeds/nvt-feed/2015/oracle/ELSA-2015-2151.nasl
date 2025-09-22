# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122755");
  script_cve_id("CVE-2012-2150");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:28 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-2151)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2151");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2151.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xfsprogs' package(s) announced via the ELSA-2015-2151 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.2.2-2]
- Fix xfs_metadump disclosure flaw, CVE-2012-2150 (#1251118)

[3.2.2-1]
- Update to upstream v3.2.2, plus fixes from v3.2.3 (#1223991)
- repair: fix unnecessary secondary scan if only last sb is corrupt (#1201238)
- repair: check ino alignment value to avoid mod by zero (#1223444)");

  script_tag(name:"affected", value:"'xfsprogs' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"xfsprogs", rpm:"xfsprogs~3.2.2~2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xfsprogs-devel", rpm:"xfsprogs-devel~3.2.2~2.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xfsprogs-qa-devel", rpm:"xfsprogs-qa-devel~3.2.2~2.el7", rls:"OracleLinux7"))) {
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
