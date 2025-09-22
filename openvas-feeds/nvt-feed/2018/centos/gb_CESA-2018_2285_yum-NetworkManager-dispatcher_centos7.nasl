# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882934");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-10 05:59:57 +0200 (Fri, 10 Aug 2018)");
  script_cve_id("CVE-2018-10897");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 12:42:00 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for yum-NetworkManager-dispatcher CESA-2018:2285 centos7");
  script_tag(name:"summary", value:"Check the version of yum-NetworkManager-dispatcher");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The yum-utils packages provide a collection of utilities and examples for
the yum package manager to make yum easier and more powerful to use.

Security Fix(es):

  * yum-utils: reposync: improper path validation may lead to directory
traversal (CVE-2018-10897)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Jay Grizzard (Clover Network) and Aaron Levy
(Clover Network) for reporting this issue.");
  script_tag(name:"affected", value:"yum-NetworkManager-dispatcher on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:2285");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-August/022981.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"yum-NetworkManager-dispatcher", rpm:"yum-NetworkManager-dispatcher~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-aliases", rpm:"yum-plugin-aliases~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-auto-update-debug-info", rpm:"yum-plugin-auto-update-debug-info~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-changelog", rpm:"yum-plugin-changelog~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-copr", rpm:"yum-plugin-copr~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-fastestmirror", rpm:"yum-plugin-fastestmirror~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-filter-data", rpm:"yum-plugin-filter-data~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-fs-snapshot", rpm:"yum-plugin-fs-snapshot~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-keys", rpm:"yum-plugin-keys~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-list-data", rpm:"yum-plugin-list-data~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-local", rpm:"yum-plugin-local~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-merge-conf", rpm:"yum-plugin-merge-conf~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-ovl", rpm:"yum-plugin-ovl~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-post-transaction-actions", rpm:"yum-plugin-post-transaction-actions~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-pre-transaction-actions", rpm:"yum-plugin-pre-transaction-actions~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-priorities", rpm:"yum-plugin-priorities~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-protectbase", rpm:"yum-plugin-protectbase~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-ps", rpm:"yum-plugin-ps~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-remove-with-leaves", rpm:"yum-plugin-remove-with-leaves~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-rpm-warm-cache", rpm:"yum-plugin-rpm-warm-cache~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-show-leaves", rpm:"yum-plugin-show-leaves~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-tmprepo", rpm:"yum-plugin-tmprepo~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-tsflags", rpm:"yum-plugin-tsflags~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-upgrade-helper", rpm:"yum-plugin-upgrade-helper~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-verify", rpm:"yum-plugin-verify~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-plugin-versionlock", rpm:"yum-plugin-versionlock~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-updateonboot", rpm:"yum-updateonboot~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yum-utils", rpm:"yum-utils~1.1.31~46.el7_5", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
