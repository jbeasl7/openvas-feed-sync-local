# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0107");
  script_cve_id("CVE-2004-0947", "CVE-2004-1027");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2024-02-01T14:37:14+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:14 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2023-0107)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0107");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0107.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31546");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unarj' package(s) announced via the MGASA-2023-0107 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer overflow in unarj before 2.63a-r2 allows remote attackers to execute
arbitrary code via an arj archive that contains long filenames.
(CVE-2004-0947)
Directory traversal vulnerability in the -x (extract) command line option
in unarj allows remote attackers to overwrite arbitrary files via an arj
archive with filenames that contain .. (dot dot) sequences. (CVE-2004-1027)");

  script_tag(name:"affected", value:"'unarj' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"unarj", rpm:"unarj~2.65~6.1.mga8.tainted", rls:"MAGEIA8"))) {
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
