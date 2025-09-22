# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130076");
  script_cve_id("CVE-2015-3272", "CVE-2015-3274", "CVE-2015-3275");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:26 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-24 15:08:36 +0000 (Wed, 24 Feb 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0302)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0302");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0302.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16374");
  script_xref(name:"URL", value:"https://docs.moodle.org/dev/Moodle_2.8.7_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=316289");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=316662");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=316664");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=316665");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2015-0302 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Moodle before 2.8.7, phishing is possible when redirecting to external
site using referer headers in error messages (CVE-2015-3272).

In Moodle before 2.8.7, several web services returning user information
did not clean text in text custom profile fields, leading to possible XSS
(CVE-2015-3274).

In Moodle before 2.8.7, possible Javascript injection was discovered in
the SCORM module (CVE-2015-3275).

As Moodle 2.6 is no longer supported, users of this package on Mageia 4
are advised to migrate to Mageia 5.");

  script_tag(name:"affected", value:"'moodle' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.8.7~1.mga5", rls:"MAGEIA5"))) {
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
