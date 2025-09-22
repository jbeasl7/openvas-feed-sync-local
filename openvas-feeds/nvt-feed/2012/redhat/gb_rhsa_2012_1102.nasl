# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-July/msg00021.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870795");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-07-23 10:46:39 +0530 (Mon, 23 Jul 2012)");
  script_cve_id("CVE-2012-1178", "CVE-2012-2318", "CVE-2012-3374");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2012:1102-01");
  script_name("RedHat Update for pidgin RHSA-2012:1102-01");

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

  A flaw was found in the way the Pidgin MSN protocol plug-in processed text
  that was not encoded in UTF-8. A remote attacker could use this flaw to
  crash Pidgin by sending a specially-crafted MSN message. (CVE-2012-1178)

  An input validation flaw was found in the way the Pidgin MSN protocol
  plug-in handled MSN notification messages. A malicious server or a remote
  attacker could use this flaw to crash Pidgin by sending a specially-crafted
  MSN notification message. (CVE-2012-2318)

  A buffer overflow flaw was found in the Pidgin MXit protocol plug-in. A
  remote attacker could use this flaw to crash Pidgin by sending a MXit
  message containing specially-crafted emoticon tags. (CVE-2012-3374)

  All Pidgin users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.7.9~5.el6.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.7.9~5.el6.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-debuginfo", rpm:"pidgin-debuginfo~2.7.9~5.el6.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
