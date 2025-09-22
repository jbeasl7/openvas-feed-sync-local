# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131248");
  script_cve_id("CVE-2012-6687");
  script_tag(name:"creation_date", value:"2016-03-03 12:39:18 +0000 (Thu, 03 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2016-0089)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0089");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0089.html");
  script_xref(name:"URL", value:"http://lwn.net/Alerts/677312/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17823");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-FCGI' package(s) announced via the MGASA-2016-0089 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated fcgi packages fix security vulnerability:

FCGI does not perform range checks for file descriptors before use of the
FD_SET macro. This FD_SET macro could allow for more than 1024 total file
descriptors to be monitored in the closing state. This may allow remote
attackers to cause a denial of service (stack memory corruption, and infinite
loop or daemon crash) by opening many socket connections to the host and
crashing the service (CVE-2012-6687).");

  script_tag(name:"affected", value:"'perl-FCGI' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-FCGI", rpm:"perl-FCGI~0.770.0~4.1.mga5", rls:"MAGEIA5"))) {
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
