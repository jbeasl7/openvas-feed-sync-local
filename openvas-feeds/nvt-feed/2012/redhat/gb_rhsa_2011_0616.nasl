# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00023.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870637");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:38:27 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-1091");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2011:0616-01");
  script_name("RedHat Update for pidgin RHSA-2011:0616-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"pidgin on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  Multiple NULL pointer dereference flaws were found in the way the Pidgin
  Yahoo! Messenger Protocol plug-in handled malformed YMSG packets. A remote
  attacker could use these flaws to crash Pidgin via a specially-crafted
  notification message. (CVE-2011-1091)

  Red Hat would like to thank the Pidgin project for reporting these issues.
  Upstream acknowledges Marius Wachtler as the original reporter.

  This update also fixes the following bugs:

  * Previous versions of the pidgin package did not properly clear certain
  data structures used in libpurple/cipher.c when attempting to free them.
  Partial information could potentially be extracted from the incorrectly
  cleared regions of the previously freed memory. With this update, data
  structures are properly cleared when freed. (BZ#684685)

  * This erratum upgrades Pidgin to upstream version 2.7.9. For a list of all
  changes addressed in this upgrade, (BZ#616917)

  * Some incomplete translations for the kn_IN and ta_IN locales have been
  corrected. (BZ#633860, BZ#640170)

  Users of pidgin should upgrade to these updated packages, which resolve
  these issues. Pidgin must be restarted for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://developer.pidgin.im/wiki/ChangeLog");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.7.9~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.7.9~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-debuginfo", rpm:"pidgin-debuginfo~2.7.9~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
