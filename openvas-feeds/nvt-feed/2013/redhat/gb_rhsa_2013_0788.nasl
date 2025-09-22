# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.870991");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-05-09 10:21:58 +0530 (Thu, 09 May 2013)");
  script_cve_id("CVE-2012-6137");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("RedHat Update for subscription-manager RHSA-2013:0788-01");

  script_xref(name:"RHSA", value:"2013:0788-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-May/msg00003.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'subscription-manager'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(6|5)");
  script_tag(name:"affected", value:"subscription-manager on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The subscription-manager packages provide programs and libraries to allow
  users to manage subscriptions and yum repositories from the Red Hat
  Entitlement platform.

  It was discovered that the rhn-migrate-classic-to-rhsm tool did not verify
  the Red Hat Network Classic server's X.509 certificate when migrating
  system profiles registered with Red Hat Network Classic to
  Certificate-based Red Hat Network. An attacker could use this flaw to
  conduct man-in-the-middle attacks, allowing them to obtain the user's Red
  Hat Network credentials. (CVE-2012-6137)

  This issue was discovered by Florian Weimer of the Red Hat Product Security
  Team.

  All users of subscription-manager are advised to upgrade to these updated
  packages, which contain a backported patch to fix this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"subscription-manager", rpm:"subscription-manager~1.1.23.1~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-debuginfo", rpm:"subscription-manager-debuginfo~1.1.23.1~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-firstboot", rpm:"subscription-manager-firstboot~1.1.23.1~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-gui", rpm:"subscription-manager-gui~1.1.23.1~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-migration", rpm:"subscription-manager-migration~1.1.23.1~1.el6_4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"subscription-manager", rpm:"subscription-manager~1.0.24.1~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-debuginfo", rpm:"subscription-manager-debuginfo~1.0.24.1~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-firstboot", rpm:"subscription-manager-firstboot~1.0.24.1~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-gui", rpm:"subscription-manager-gui~1.0.24.1~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-migration", rpm:"subscription-manager-migration~1.0.24.1~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
