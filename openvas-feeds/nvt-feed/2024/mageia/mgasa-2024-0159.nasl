# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0159");
  script_cve_id("CVE-2020-8908", "CVE-2023-2976");
  script_tag(name:"creation_date", value:"2024-05-01 04:12:41 +0000 (Wed, 01 May 2024)");
  script_version("2024-05-02T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-05-02 05:05:31 +0000 (Thu, 02 May 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-28 18:56:30 +0000 (Wed, 28 Jun 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0159)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0159");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0159.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33071");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'guava' package(s) announced via the MGASA-2024-0159 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A bug that could allow an attacker with access to the machine to
potentially access data in a temporary directory created by the Guava.
(CVE-2020-8908)
Predictable temporary files and directories used in
FileBackedOutputStream. (CVE-2023-2976)");

  script_tag(name:"affected", value:"'guava' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"guava", rpm:"guava~32.0.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"guava-javadoc", rpm:"guava-javadoc~32.0.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"guava-testlib", rpm:"guava-testlib~32.0.1~1.mga9", rls:"MAGEIA9"))) {
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
