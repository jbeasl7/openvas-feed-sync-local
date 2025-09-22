# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882969");
  script_version("2023-07-10T08:07:43+0000");
  script_cve_id("CVE-2018-1000805");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-06 18:35:00 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"creation_date", value:"2018-11-09 06:05:02 +0100 (Fri, 09 Nov 2018)");
  script_name("CentOS Update for python-paramiko CESA-2018:3406 centos6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2018:3406");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-November/023076.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-paramiko'
  package(s) announced via the CESA-2018:3406 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The python-paramiko package provides a Python module that implements the
SSH2 protocol for encrypted and authenticated connections to remote
machines. Unlike SSL, the SSH2 protocol does not require hierarchical
certificates signed by a powerful central authority. The protocol also
includes the ability to open arbitrary channels to remote services across
an encrypted tunnel.

Security Fix(es):

  * python-paramiko: Authentication bypass in auth_handler.py
(CVE-2018-1000805)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.");

  script_tag(name:"affected", value:"python-paramiko on CentOS 6.");

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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"python-paramiko", rpm:"python-paramiko~1.7.5~5.el6_10", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
