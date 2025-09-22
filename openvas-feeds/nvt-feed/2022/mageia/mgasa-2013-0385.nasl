# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0385");
  script_cve_id("CVE-2013-1438", "CVE-2013-1439");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0385)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0385");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0385.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1978-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12074");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libkdcraw' package(s) announced via the MGASA-2013-0385 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libkdcraw packages fix libraw security vulnerabilities:

It was discovered that LibRaw incorrectly handled photo files. If a user or
automated system were tricked into processing a specially crafted photo
file, applications linked against LibRaw could be made to crash, resulting
in a denial of service (CVE-2013-1438, CVE-2013-1439).");

  script_tag(name:"affected", value:"'libkdcraw' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64kdcraw-devel", rpm:"lib64kdcraw-devel~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdcraw22", rpm:"lib64kdcraw22~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdcraw", rpm:"libkdcraw~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdcraw-common", rpm:"libkdcraw-common~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdcraw-devel", rpm:"libkdcraw-devel~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdcraw22", rpm:"libkdcraw22~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
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
