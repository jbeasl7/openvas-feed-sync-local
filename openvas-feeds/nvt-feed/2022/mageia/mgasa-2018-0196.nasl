# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0196");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2018-0196)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0196");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0196.html");
  script_xref(name:"URL", value:"http://seclists.org/nmap-announce/2018/0");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22854");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nmap' package(s) announced via the MGASA-2018-0196 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nmap developer nnposter found a security flaw (directory traversal
vulnerability) in the way the non-default http-fetch script sanitized
URLs. If a user manually ran this NSE script against a malicious web
server, the server could potentially (depending on NSE arguments used)
cause files to be saved outside the intended destination directory.
Existing files couldn't be overwritten. We fixed http-fetch, audited
our other scripts to ensure they didn't make this mistake, and updated
the httpspider library API to protect against this by default.");

  script_tag(name:"affected", value:"'nmap' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"nmap", rpm:"nmap~7.40~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nmap-frontend", rpm:"nmap-frontend~7.40~1.1.mga6", rls:"MAGEIA6"))) {
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
