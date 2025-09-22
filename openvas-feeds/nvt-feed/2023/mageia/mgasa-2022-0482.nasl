# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0482");
  script_cve_id("CVE-2022-41859", "CVE-2022-41860", "CVE-2022-41861");
  script_tag(name:"creation_date", value:"2023-01-02 04:14:00 +0000 (Mon, 02 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-24 19:53:50 +0000 (Tue, 24 Jan 2023)");

  script_name("Mageia: Security Advisory (MGASA-2022-0482)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0482");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0482.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31291");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/GZM4O5MGLKNOE2SSXAXQNL5DSII556QA/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YGQKLVAIGSOB2CSLQ2ASBK2MJAHL4LCI/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius' package(s) announced via the MGASA-2022-0482 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Information leakage in EAP-PWD. (CVE-2022-41859)
Crash on unknown option in EAP-SIM. (CVE-2022-41860)
Crash on invalid abinary data. (CVE-2022-41861)");

  script_tag(name:"affected", value:"'freeradius' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-krb5", rpm:"freeradius-krb5~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-ldap", rpm:"freeradius-ldap~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-mysql", rpm:"freeradius-mysql~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-postgresql", rpm:"freeradius-postgresql~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-sqlite", rpm:"freeradius-sqlite~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-unixODBC", rpm:"freeradius-unixODBC~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeradius-yubikey", rpm:"freeradius-yubikey~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freeradius-devel", rpm:"lib64freeradius-devel~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freeradius1", rpm:"lib64freeradius1~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreeradius-devel", rpm:"libfreeradius-devel~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreeradius1", rpm:"libfreeradius1~3.0.22~1.1.mga8", rls:"MAGEIA8"))) {
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
