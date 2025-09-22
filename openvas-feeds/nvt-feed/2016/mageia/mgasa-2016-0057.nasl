# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131221");
  script_cve_id("CVE-2015-8748");
  script_tag(name:"creation_date", value:"2016-02-11 05:22:20 +0000 (Thu, 11 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-16 18:42:20 +0000 (Tue, 16 Feb 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0057)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0057");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0057.html");
  script_xref(name:"URL", value:"http://radicale.org/news/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17452");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3462");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'radicale' package(s) announced via the MGASA-2016-0057 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated radicale package fixes security vulnerabilities:

If an attacker is able to authenticate with a user name like `.*', he can
bypass read/write limitations imposed by regex-based rules, including the
built-in rules `owner_write' (read for everybody, write for the calendar
owner) and `owner_only' (read and write for the calendar owner)
(CVE-2015-8748).

The radicale package has been updated to version 1.1.1, fixing this issue and
several other security issues.");

  script_tag(name:"affected", value:"'radicale' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"radicale", rpm:"radicale~1.1.1~1.1.mga5", rls:"MAGEIA5"))) {
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
