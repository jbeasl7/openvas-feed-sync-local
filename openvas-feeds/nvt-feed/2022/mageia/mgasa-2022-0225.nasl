# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0225");
  script_cve_id("CVE-2022-24450");
  script_tag(name:"creation_date", value:"2022-06-14 04:45:21 +0000 (Tue, 14 Jun 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-11 15:59:34 +0000 (Fri, 11 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0225)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0225");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0225.html");
  script_xref(name:"URL", value:"https://advisories.nats.io/CVE/CVE-2022-24450.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30013");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nats-server' package(s) announced via the MGASA-2022-0225 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NATS nats-server before 2.7.2 has Incorrect Access Control. Any
authenticated user can obtain the privileges of the System account by
misusing the 'dynamically provisioned sandbox accounts' feature.
(CVE-2022-24450)");

  script_tag(name:"affected", value:"'nats-server' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-golang-github-nats-io-gnatsd-devel", rpm:"compat-golang-github-nats-io-gnatsd-devel~2.1.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compat-golang-github-nats-io-server-2-devel", rpm:"compat-golang-github-nats-io-server-2-devel~2.1.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nats-io-server-devel", rpm:"golang-github-nats-io-server-devel~2.1.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nats-server", rpm:"nats-server~2.1.9~1.1.mga8", rls:"MAGEIA8"))) {
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
