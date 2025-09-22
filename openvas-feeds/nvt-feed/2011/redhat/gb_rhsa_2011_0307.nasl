# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-March/msg00003.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870398");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name:"RHSA", value:"2011:0307-01");
  script_cve_id("CVE-2008-0564", "CVE-2010-3089", "CVE-2011-0707");
  script_name("RedHat Update for mailman RHSA-2011:0307-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mailman'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(5|4)");
  script_tag(name:"affected", value:"mailman on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mailman is a program used to help manage email discussion lists.

  Multiple input sanitization flaws were found in the way Mailman displayed
  usernames of subscribed users on certain pages. If a user who is subscribed
  to a mailing list were able to trick a victim into visiting one of those
  pages, they could perform a cross-site scripting (XSS) attack against the
  victim. (CVE-2011-0707)

  Multiple input sanitization flaws were found in the way Mailman displayed
  mailing list information. A mailing list administrator could use this flaw
  to conduct a cross-site scripting (XSS) attack against victims viewing a
  list's 'listinfo' page. (CVE-2008-0564, CVE-2010-3089)

  Red Hat would like to thank Mark Sapiro for reporting the CVE-2011-0707 and
  CVE-2010-3089 issues.

  Users of mailman should upgrade to this updated package, which contains
  backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.9~6.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mailman-debuginfo", rpm:"mailman-debuginfo~2.1.9~6.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.5.1~34.rhel4.7", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mailman-debuginfo", rpm:"mailman-debuginfo~2.1.5.1~34.rhel4.7", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
