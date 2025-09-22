# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0194");
  script_cve_id("CVE-2020-7677", "CVE-2021-43138", "CVE-2022-3517", "CVE-2022-37599", "CVE-2023-26136", "CVE-2023-46234", "CVE-2024-12905", "CVE-2024-37890", "CVE-2024-4067", "CVE-2024-48949", "CVE-2025-48387");
  script_tag(name:"creation_date", value:"2025-06-25 06:26:30 +0000 (Wed, 25 Jun 2025)");
  script_version("2025-06-26T05:40:52+0000");
  script_tag(name:"last_modification", value:"2025-06-26 05:40:52 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-08 00:02:00 +0000 (Sat, 08 Jul 2023)");

  script_name("Mageia: Security Advisory (MGASA-2025-0194)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0194");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0194.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33674");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/2UGLXZO6VIHGIITQTEUY5Q5YCAP2A4ZP/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VEDIJM7VQF4Q2L2KKQ6KJ2WZNR7AXYQD/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yarnpkg' package(s) announced via the MGASA-2025-0194 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-37890 yarnpkg: denial of service when handling a request with
many HTTP headers.
CVE-2024-48949 yarnpkg: Missing Validation in Elliptic's EDDSA Signature
Verification.
CVE-2024-12905 yarnpkg: link following and path traversal via
maliciously crafted tar file
And other vulnerabilities in the yarn's bundled nodejs components are
fixed too, see the references.");

  script_tag(name:"affected", value:"'yarnpkg' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"yarnpkg", rpm:"yarnpkg~1.22.22~0.10.9.2.1.mga9", rls:"MAGEIA9"))) {
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
