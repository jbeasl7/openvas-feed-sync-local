# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882590");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-13 05:45:22 +0100 (Sun, 13 Nov 2016)");
  script_cve_id("CVE-2016-7035");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for pacemaker CESA-2016:2675 centos6");
  script_tag(name:"summary", value:"Check the version of pacemaker");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Pacemaker cluster resource manager is
a collection of technologies working together to provide data integrity and the
ability to maintain application availability in the event of a failure.

Security Fix(es):

  * An authorization flaw was found in Pacemaker, where it did not properly
guard its IPC interface. An attacker with an unprivileged account on a
Pacemaker node could use this flaw to, for example, force the Local
Resource Manager daemon to execute a script as root and thereby gain root
access on the machine. (CVE-2016-7035)

This issue was discovered by Jan 'poki' Pokorny (Red Hat) and Alain Moulle
(ATOS/BULL).");
  script_tag(name:"affected", value:"pacemaker on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:2675");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-November/022142.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"pacemaker", rpm:"pacemaker~1.1.14~8.el6_8.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-cli", rpm:"pacemaker-cli~1.1.14~8.el6_8.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-cluster-libs", rpm:"pacemaker-cluster-libs~1.1.14~8.el6_8.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-cts", rpm:"pacemaker-cts~1.1.14~8.el6_8.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-doc", rpm:"pacemaker-doc~1.1.14~8.el6_8.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-libs", rpm:"pacemaker-libs~1.1.14~8.el6_8.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-libs-devel", rpm:"pacemaker-libs-devel~1.1.14~8.el6_8.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pacemaker-remote", rpm:"pacemaker-remote~1.1.14~8.el6_8.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
