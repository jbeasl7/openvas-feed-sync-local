# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122745");
  script_cve_id("CVE-2015-3258", "CVE-2015-3279");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:21 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-2360)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2360");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2360.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups-filters' package(s) announced via the ELSA-2015-2360 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.0.35-21]
- Fix heap-based buffer overflow in texttopdf filter (bug #1241242,
 CVE-2015-3258, CVE-2015-3279).

[1.0.35-20]
- Improvements to cups-browsed efficiency patch (bug #1191691).

[1.0.35-18]
- Fix segfault in texttopdf filter (bug #1194263).
- Improve cups-browsed efficiency (bug #1191691).
- Fetch printer descriptions with cups-browsed (bug #1223719).
- Fix cups-browsed '_' handling for printer names (bug #1167408).

[1.0.35-17]
- Build against newer poppler (bug #1217552).

[1.0.35-16]
- Applied upstream patch to fix BrowseAllow parsing issue
 (CVE-2014-4338, bug #1091568).
- Applied upstream patch for cups-browsed DoS via
 process_browse_data() out-of-bounds read (CVE-2014-4337,
 bug #1111510).");

  script_tag(name:"affected", value:"'cups-filters' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups-filters", rpm:"cups-filters~1.0.35~21.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-filters-devel", rpm:"cups-filters-devel~1.0.35~21.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-filters-libs", rpm:"cups-filters-libs~1.0.35~21.el7", rls:"OracleLinux7"))) {
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
