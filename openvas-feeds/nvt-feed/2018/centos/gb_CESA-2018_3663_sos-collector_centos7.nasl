# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882975");
  script_version("2023-07-10T08:07:43+0000");
  script_cve_id("CVE-2018-14650");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:35:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-12-18 07:37:12 +0100 (Tue, 18 Dec 2018)");
  script_name("CentOS Update for sos-collector CESA-2018:3663 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2018:3663");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-December/023126.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sos-collector'
  package(s) announced via the CESA-2018:3663 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"sos-collector is a utility that gathers sosreports from multi-node
environments. sos-collector facilitates data collection for support cases
and it can be run from either a node or from an administrator's local
workstation that has network access to the environment.

The following packages have been upgraded to a later upstream version:
sos-collector (1.5). (BZ#1644776)

Security Fix(es):

  * sos-collector: incorrect permissions set on newly created files
(CVE-2018-14650)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

This issue was discovered by Riccardo Schirone (Red Hat Product Security).");

  script_tag(name:"affected", value:"sos-collector on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"sos-collector", rpm:"sos-collector~1.5~3.el7_6", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
