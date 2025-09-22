# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0080");
  script_cve_id("CVE-2013-6890");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0080)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0080");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0080.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2826");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12092");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2014/msg00018.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'denyhosts' package(s) announced via the MGASA-2014-0080 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Helmut Grohne discovered that denyhosts, a tool preventing SSH brute-force
attacks, could be used to perform remote denial of service against the SSH
daemon. Incorrectly specified regular expressions used to detect brute
force attacks in authentication logs could be exploited by a malicious
user to forge crafted login names in order to make denyhosts ban arbitrary
IP addresses (CVE-2013-6890).

This update also includes a fix for a regression introduced when fixing
CVE-2013-6890.");

  script_tag(name:"affected", value:"'denyhosts' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"denyhosts", rpm:"denyhosts~2.6~4.4.mga3", rls:"MAGEIA3"))) {
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
