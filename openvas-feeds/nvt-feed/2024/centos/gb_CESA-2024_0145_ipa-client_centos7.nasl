# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884330");
  script_version("2024-04-11T05:05:26+0000");
  script_cve_id("CVE-2023-5455");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-04-11 05:05:26 +0000 (Thu, 11 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 19:05:40 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-03-05 14:33:40 +0000 (Tue, 05 Mar 2024)");
  script_name("CentOS: Security Advisory for ipa-client (CESA-2024:0145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2024:0145");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2024-January/099176.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa-client'
  package(s) announced via the CESA-2024:0145 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Red Hat Identity Management (IdM) is a centralized authentication, identity management, and authorization solution for both traditional and cloud-based enterprise environments.

Security Fix(es):

  * ipa: Invalid CSRF protection (CVE-2023-5455)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.");

  script_tag(name:"affected", value:"'ipa-client' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-client-common", rpm:"ipa-client-common~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-common", rpm:"ipa-common~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-python-compat", rpm:"ipa-python-compat~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-common", rpm:"ipa-server-common~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-dns", rpm:"ipa-server-dns~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-ipaclient", rpm:"python2-ipaclient~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-ipalib", rpm:"python2-ipalib~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-ipaserver", rpm:"python2-ipaserver~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa", rpm:"ipa~4.6.8~5.el7.centos.16", rls:"CentOS7"))) {
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