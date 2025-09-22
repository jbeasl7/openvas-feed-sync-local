# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883116");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2019-14823");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-25 19:15:00 +0000 (Fri, 25 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-22 02:01:53 +0000 (Tue, 22 Oct 2019)");
  script_name("CentOS Update for jss CESA-2019:3067 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:3067");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-October/023481.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jss'
  package(s) announced via the CESA-2019:3067 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Java Security Services (JSS) provides an interface between Java Virtual
Machine and Network Security Services (NSS). It supports most of the
security standards and encryption technologies supported by NSS including
communication through SSL/TLS network protocols. JSS is primarily utilized
by the Certificate Server as a part of the Identity Management System.

Security Fix(es):

  * JSS: OCSP policy 'Leaf and Chain' implicitly trusts the root certificate
(CVE-2019-14823)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'jss' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"jss", rpm:"jss~4.4.6~3.el7_7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jss-javadoc", rpm:"jss-javadoc~4.4.6~3.el7_7", rls:"CentOS7"))) {
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
