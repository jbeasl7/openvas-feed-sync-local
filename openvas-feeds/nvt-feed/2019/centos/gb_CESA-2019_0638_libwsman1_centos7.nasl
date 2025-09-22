# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883046");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2019-3816");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-02 20:17:00 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2019-05-01 02:01:02 +0000 (Wed, 01 May 2019)");
  script_name("CentOS Update for libwsman1 CESA-2019:0638 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:0638");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-April/023295.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwsman1'
  package(s) announced via the CESA-2019:0638 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Openwsman is a project intended to provide an open source implementation of
the Web Services Management specification (WS-Management) and to expose
system management information on the Linux operating system using the
WS-Management protocol. WS-Management is based on a suite of web services
specifications and usage requirements that cover all system management
aspects.

Security Fix(es):

  * openwsman: Disclosure of arbitrary files outside of the registered URIs
(CVE-2019-3816)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'libwsman1' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"libwsman1", rpm:"libwsman1~2.6.3~6.git4391e5c.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsman-devel", rpm:"libwsman-devel~2.6.3~6.git4391e5c.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-client", rpm:"openwsman-client~2.6.3~6.git4391e5c.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-perl", rpm:"openwsman-perl~2.6.3~6.git4391e5c.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-python", rpm:"openwsman-python~2.6.3~6.git4391e5c.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-ruby", rpm:"openwsman-ruby~2.6.3~6.git4391e5c.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman-server", rpm:"openwsman-server~2.6.3~6.git4391e5c.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openwsman", rpm:"openwsman~2.6.3~6.git4391e5c.el7_6", rls:"CentOS7"))) {
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
