# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0120");
  script_cve_id("CVE-2025-2361");
  script_tag(name:"creation_date", value:"2025-04-01 04:08:15 +0000 (Tue, 01 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-17 05:15:36 +0000 (Mon, 17 Mar 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0120)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0120");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0120.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34129");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2025/msg00045.html");
  script_xref(name:"URL", value:"https://lists.mercurial-scm.org/pipermail/mercurial-packaging/2025-March/000754.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/03/21/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mercurial' package(s) announced via the MGASA-2025-0120 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mercurial SCM Web Interface cross site scripting. (CVE-2025-2361)");

  script_tag(name:"affected", value:"'mercurial' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"mercurial", rpm:"mercurial~6.5.1~1.1.mga9", rls:"MAGEIA9"))) {
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
