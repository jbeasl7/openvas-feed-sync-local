# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131242");
  script_cve_id("CVE-2016-0741");
  script_tag(name:"creation_date", value:"2016-02-23 14:01:20 +0000 (Tue, 23 Feb 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-21 15:12:46 +0000 (Thu, 21 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0081)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0081");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0081.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17784");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2016-0204.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the MGASA-2016-0081 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An infinite-loop vulnerability was discovered in the 389 directory server,
where the server failed to correctly handle unexpectedly closed client
connections. A remote attacker able to connect to the server could use
this flaw to make the directory server consume an excessive amount of CPU
and stop accepting connections (denial of service) (CVE-2016-0741).");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.4.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-ds-base-devel", rpm:"lib389-ds-base-devel~1.3.4.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib389-ds-base0", rpm:"lib389-ds-base0~1.3.4.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64389-ds-base-devel", rpm:"lib64389-ds-base-devel~1.3.4.8~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64389-ds-base0", rpm:"lib64389-ds-base0~1.3.4.8~1.mga5", rls:"MAGEIA5"))) {
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
