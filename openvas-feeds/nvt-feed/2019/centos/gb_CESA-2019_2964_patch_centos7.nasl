# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883119");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2018-20969", "CVE-2019-13638");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-05 16:15:00 +0000 (Thu, 05 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-10-24 02:00:55 +0000 (Thu, 24 Oct 2019)");
  script_name("CentOS Update for patch CESA-2019:2964 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:2964");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-October/023495.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'patch'
  package(s) announced via the CESA-2019:2964 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The patch program applies diff files to originals. The diff command is used
to compare an original to a changed file. Diff lists the changes made to
the file. A person who has the original file can then use the patch command
with the diff file to add the changes to their original file (patching the
file).

Security Fix(es):

  * patch: do_ed_script in pch.c does not block strings beginning with a !
character (CVE-2018-20969)

  * patch: OS shell command injection when processing crafted patch files
(CVE-2019-13638)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'patch' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"patch", rpm:"patch~2.7.1~12.el7_7", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
