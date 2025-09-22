# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0103");
  script_cve_id("CVE-2021-32803", "CVE-2021-32804", "CVE-2021-37701", "CVE-2021-37712");
  script_tag(name:"creation_date", value:"2022-03-22 04:07:04 +0000 (Tue, 22 Mar 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 18:02:56 +0000 (Thu, 09 Sep 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0103)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0103");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0103.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29656");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5008");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs-tar' package(s) announced via the MGASA-2022-0103 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Untrusted tar file to symlink into an arbitrary location allowing file
overwrites. (CVE-2021-37712)

Arbitrary file creation/overwrite and arbitrary code execution.
(CVE-2021-37701)

Arbitrary File Creation/Overwrite vulnerability via insufficient symlink
protection. (CVE-2021-32803)

Arbitrary File Creation/Overwrite vulnerability due to insufficient
absolute path sanitization (CVE-2021-32804)");

  script_tag(name:"affected", value:"'nodejs-tar' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs-tar", rpm:"nodejs-tar~6.0.5~1.1.mga8", rls:"MAGEIA8"))) {
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
