# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130089");
  script_cve_id("CVE-2015-3644");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:34 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0289)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0289");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0289.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15891");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3299");
  script_xref(name:"URL", value:"https://www.stunnel.org/CVE-2015-3644.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'stunnel' package(s) announced via the MGASA-2015-0289 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Johan Olofsson discovered an authentication bypass vulnerability in
Stunnel, a program designed to work as an universal SSL tunnel for network
daemons. When Stunnel in server mode is used with the redirect option and
certificate-based authentication is enabled with 'verify = 2' or higher,
then only the initial connection is redirected to the hosts specified with
'redirect'. This allows a remote attacker to bypass authentication
(CVE-2015-3644).");

  script_tag(name:"affected", value:"'stunnel' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"stunnel", rpm:"stunnel~5.03~4.1.mga5", rls:"MAGEIA5"))) {
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
