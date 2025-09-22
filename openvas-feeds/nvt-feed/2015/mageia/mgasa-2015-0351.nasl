# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130036");
  script_cve_id("CVE-2015-0899");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:50 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-06 14:48:02 +0000 (Wed, 06 Jul 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0351)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0351");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0351.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16601");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-September/165517.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'struts' package(s) announced via the MGASA-2015-0351 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated struts packages fix security vulnerability:

The Validator in Apache Struts 1.1 and later contains a function to
efficiently define rules for input validation across multiple pages during
screen transitions. This function contains a vulnerability where input
validation may be bypassed. When the Apache Struts 1 Validator is used, the
web application may be vulnerable even when this function is not used
explicitly (CVE-2015-0899).");

  script_tag(name:"affected", value:"'struts' package(s) on Mageia 4, Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"struts", rpm:"struts~1.3.10~4.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"struts-javadoc", rpm:"struts-javadoc~1.3.10~4.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"struts", rpm:"struts~1.3.10~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"struts-javadoc", rpm:"struts-javadoc~1.3.10~8.1.mga5", rls:"MAGEIA5"))) {
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
