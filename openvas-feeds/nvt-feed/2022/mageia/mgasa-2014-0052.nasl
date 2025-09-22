# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0052");
  script_cve_id("CVE-2014-0021");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-03 19:53:48 +0000 (Tue, 03 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2014-0052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0052");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0052.html");
  script_xref(name:"URL", value:"http://chrony.tuxfamily.org/News.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12347");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chrony' package(s) announced via the MGASA-2014-0052 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated chrony package fixes security vulnerability:

In the chrony control protocol some replies are significantly larger than
their requests, which allows an attacker to use it in an amplification
attack (CVE-2014-0021).

Note: in the default configuration, cmdallow is restricted to localhost,
so significant amplification is only possible if the configuration has
been changed to allow cmdallow from other hosts. Even from hosts whose
access is denied, minor amplification is still possible.");

  script_tag(name:"affected", value:"'chrony' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"chrony", rpm:"chrony~1.29.1~1.mga4", rls:"MAGEIA4"))) {
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
