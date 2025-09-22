# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122880");
  script_cve_id("CVE-2016-0741");
  script_tag(name:"creation_date", value:"2016-02-18 05:27:22 +0000 (Thu, 18 Feb 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-12 02:01:00 +0000 (Wed, 12 Oct 2016)");

  script_name("Oracle: Security Advisory (ELSA-2016-0204)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0204");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0204.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the ELSA-2016-0204 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.3.4.0-26]
- release 1.3.4.0-26
- Resolves: bug 1299346 - deadlock on connection mutex (DS 48341)

[1.3.4.0-25]
- release 1.3.4.0-25
- Resolves: bug 1299757 - CVE-2016-0741 389-ds-base: Worker threads do not detect abnormally closed connections causing DoS

[1.3.4.0-24]
- release 1.3.4.0-24
- Resolves: bug 1298105 - 389-ds hanging after a few minutes of operation (DS 48406)

[1.3.4.0-23]
- release 1.3.4.0-23
- Resolves: bug 1295684 - many attrlist_replace errors in connection with cleanallruv (DS 48283)

[1.3.4.0-22]
- release 1.3.4.0-22
- Resolves: bug 1290725 - SimplePagedResults -- in the search error case, simple paged results slot was not released. (DS 48375)
- Resolves: bug 1290726 - The 'eq' index does not get updated properly when deleting and re-adding attributes in the same modify operation (DS 48370)");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.4.0~26.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.4.0~26.el7_2", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.4.0~26.el7_2", rls:"OracleLinux7"))) {
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
