# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882746");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-30 05:12:12 +0200 (Fri, 30 Jun 2017)");
  script_cve_id("CVE-2017-9462");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 18:32:00 +0000 (Wed, 05 Feb 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for emacs-mercurial CESA-2017:1576 centos7");
  script_tag(name:"summary", value:"Check the version of emacs-mercurial");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mercurial is a fast, lightweight source
control management system designed for efficient handling of very large
distributed projects.

Security Fix(es):

  * A flaw was found in the way 'hg serve --stdio' command in Mercurial
handled command-line options. A remote, authenticated attacker could use
this flaw to execute arbitrary code on the Mercurial server by using
specially crafted command-line options. (CVE-2017-9462)");
  script_tag(name:"affected", value:"emacs-mercurial on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:1576");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-June/022488.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"emacs-mercurial", rpm:"emacs-mercurial~2.6.2~7.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"emacs-mercurial-el", rpm:"emacs-mercurial-el~2.6.2~7.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mercurial", rpm:"mercurial~2.6.2~7.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mercurial-hgk", rpm:"mercurial-hgk~2.6.2~7.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
