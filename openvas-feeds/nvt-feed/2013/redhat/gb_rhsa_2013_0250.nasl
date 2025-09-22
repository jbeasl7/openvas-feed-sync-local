# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00018.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870907");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-02-15 11:15:17 +0530 (Fri, 15 Feb 2013)");
  script_cve_id("CVE-2012-4545");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2013:0250-01");
  script_name("RedHat Update for elinks RHSA-2013:0250-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elinks'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(6|5)");
  script_tag(name:"affected", value:"elinks on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"ELinks is a text-based web browser. ELinks does not display any images, but
  it does support frames, tables, and most other HTML tags.

  It was found that ELinks performed client credentials delegation during the
  client-to-server GSS security mechanisms negotiation. A rogue server could
  use this flaw to obtain the client's credentials and impersonate that
  client to other servers that are using GSSAPI. (CVE-2012-4545)

  This issue was discovered by Marko Myllynen of Red Hat.

  All ELinks users are advised to upgrade to this updated package, which
  contains a backported patch to resolve the issue.");
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

  if ((res = isrpmvuln(pkg:"elinks", rpm:"elinks~0.12~0.21.pre5.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"elinks-debuginfo", rpm:"elinks-debuginfo~0.12~0.21.pre5.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"elinks", rpm:"elinks~0.11.1~8.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"elinks-debuginfo", rpm:"elinks-debuginfo~0.11.1~8.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
