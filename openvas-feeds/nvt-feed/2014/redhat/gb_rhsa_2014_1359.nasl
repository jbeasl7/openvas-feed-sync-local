# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871256");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-10-07 06:04:12 +0200 (Tue, 07 Oct 2014)");
  script_cve_id("CVE-2014-5033");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for polkit-qt RHSA-2014:1359-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'polkit-qt'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Polkit-qt is a library that lets
developers use the PolicyKit API through a Qt-styled API. The polkit-qt
library is used by the KDE Authentication Agent (KAuth), which is a part of kdelibs.

It was found that polkit-qt handled authorization requests with PolicyKit
via a D-Bus API that is vulnerable to a race condition. A local user could
use this flaw to bypass intended PolicyKit authorizations. This update
modifies polkit-qt to communicate with PolicyKit via a different API that
is not vulnerable to the race condition. (CVE-2014-5033)

All polkit-qt users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue.");
  script_tag(name:"affected", value:"polkit-qt on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:1359-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-October/msg00004.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"polkit-qt", rpm:"polkit-qt~0.103.0~10.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"polkit-qt-debuginfo", rpm:"polkit-qt-debuginfo~0.103.0~10.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
