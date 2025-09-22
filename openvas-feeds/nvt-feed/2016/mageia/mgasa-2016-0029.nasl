# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131190");
  script_cve_id("CVE-2016-0724", "CVE-2016-0725");
  script_tag(name:"creation_date", value:"2016-01-21 05:32:02 +0000 (Thu, 21 Jan 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-24 18:59:54 +0000 (Wed, 24 Feb 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0029)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0029");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0029.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17537");
  script_xref(name:"URL", value:"https://docs.moodle.org/dev/Moodle_2.8.10_release_notes");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=325820");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=326205");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=326206");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the MGASA-2016-0029 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Moodle before 2.8.10, web services
core_enrol_get_course_enrolment_methods and
enrol_self_get_instance_info did not check user permission to access
hidden courses (CVE-2016-0724).

In Moodle before 2.8.10, search string in course management interface was
not escaped when being output creating potential for XSS attack
(CVE-2016-0725).");

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

  if(!isnull(res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.8.10~1.mga5", rls:"MAGEIA5"))) {
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
