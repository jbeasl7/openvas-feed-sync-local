# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883100");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2019-14744");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 18:26:00 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2019-09-19 02:01:12 +0000 (Thu, 19 Sep 2019)");
  script_name("CentOS Update for kdelibs CESA-2019:2606 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:2606");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-September/023418.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdelibs'
  package(s) announced via the CESA-2019:2606 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The K Desktop Environment (KDE) is a graphical desktop environment for the
X Window System. The kdelibs packages include core libraries for the K
Desktop Environment.

Security Fix(es):

  * kdelibs: malicious desktop files and configuration files lead to code
execution with minimal user interaction (CVE-2019-14744)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * kde.csh profile file contains bourne-shell code (BZ#1740042)");

  script_tag(name:"affected", value:"'kdelibs' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~4.14.8~11.el7_7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs-apidocs", rpm:"kdelibs-apidocs~4.14.8~11.el7_7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs-common", rpm:"kdelibs-common~4.14.8~11.el7_7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~4.14.8~11.el7_7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs-ktexteditor", rpm:"kdelibs-ktexteditor~4.14.8~11.el7_7", rls:"CentOS7"))) {
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
