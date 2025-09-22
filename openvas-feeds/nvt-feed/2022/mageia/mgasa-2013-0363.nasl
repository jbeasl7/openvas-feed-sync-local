# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0363");
  script_cve_id("CVE-2013-6411");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0363)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0363");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0363.html");
  script_xref(name:"URL", value:"http://gb.binaries.openttd.org/binaries/releases/1.3.3/changelog.txt");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2013/11/28/17");
  script_xref(name:"URL", value:"http://security.openttd.org/en/CVE-2013-6411");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11852");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openttd' package(s) announced via the MGASA-2013-0363 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A missing validation in OpenTTD before 1.3.3 allows remote attackers to
cause a denial of service (crash) by forcefully crashing aircraft near the
corner of the map. This triggers a corner case where data outside of the
allocated map array is accessed (CVE-2013-6411).");

  script_tag(name:"affected", value:"'openttd' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"openttd", rpm:"openttd~1.3.3~1.mga3", rls:"MAGEIA3"))) {
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
