# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884306");
  script_version("2024-04-11T05:05:26+0000");
  script_cve_id("CVE-2023-50447");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-04-11 05:05:26 +0000 (Thu, 11 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 13:50:30 +0000 (Fri, 26 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-05 14:32:07 +0000 (Tue, 05 Mar 2024)");
  script_name("CentOS: Security Advisory for python-pillow (CESA-2024:0857)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2024:0857");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2024-February/099227.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pillow'
  package(s) announced via the CESA-2024:0857 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The python-pillow packages contain a Python image processing library that provides extensive file format support, an efficient internal representation, and powerful image-processing capabilities.

Security Fix(es):

  * pillow: Arbitrary Code Execution via the environment parameter (CVE-2023-50447)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.");

  script_tag(name:"affected", value:"'python-pillow' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pillow", rpm:"python-pillow~2.0.0~25.gitd1c6db8.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pillow-devel", rpm:"python-pillow-devel~2.0.0~25.gitd1c6db8.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pillow-doc", rpm:"python-pillow-doc~2.0.0~25.gitd1c6db8.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pillow-qt", rpm:"python-pillow-qt~2.0.0~25.gitd1c6db8.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pillow-sane", rpm:"python-pillow-sane~2.0.0~25.gitd1c6db8.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pillow-tk", rpm:"python-pillow-tk~2.0.0~25.gitd1c6db8.el7_9", rls:"CentOS7"))) {
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