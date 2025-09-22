# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871259");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-10-15 06:03:26 +0200 (Wed, 15 Oct 2014)");
  script_cve_id("CVE-2014-2856", "CVE-2014-3537", "CVE-2014-5029", "CVE-2014-5030", "CVE-2014-5031");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RedHat Update for cups RHSA-2014:1388-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"CUPS provides a portable printing layer for Linux, UNIX, and similar
operating systems.

A cross-site scripting (XSS) flaw was found in the CUPS web interface.
An attacker could use this flaw to perform a cross-site scripting attack
against users of the CUPS web interface. (CVE-2014-2856)

It was discovered that CUPS allowed certain users to create symbolic links
in certain directories under /var/cache/cups/. A local user with the 'lp'
group privileges could use this flaw to read the contents of arbitrary
files on the system or, potentially, escalate their privileges on the
system. (CVE-2014-3537, CVE-2014-5029, CVE-2014-5030, CVE-2014-5031)

The CVE-2014-3537 issue was discovered by Francisco Alonso of Red Hat
Product Security.

These updated cups packages also include several bug fixes. Space precludes
documenting all of these changes in this advisory. Users are directed to
the Red Hat Enterprise Linux 6.6 Technical Notes, linked to in the
References section, for information on the most significant of these
changes.

All cups users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, the cupsd daemon will be restarted automatically.");
  script_tag(name:"affected", value:"cups on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:1388-02");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-October/msg00013.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.4.2~67.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.4.2~67.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.4.2~67.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.4.2~67.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.4.2~67.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
