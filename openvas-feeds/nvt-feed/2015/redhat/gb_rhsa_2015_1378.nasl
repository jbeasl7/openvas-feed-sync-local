# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871410");
  script_version("2024-03-21T05:06:54+0000");
  script_cve_id("CVE-2014-9273");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-07-23 06:26:56 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for hivex RHSA-2015:1378-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'hivex'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Hivex is a library that can read and
  write Hive files, undocumented binary
files that Windows uses to store the Windows Registry on disk.

It was found that hivex attempted to read, and possibly write, beyond its
allocated buffer when reading a hive file with a very small size or with a
truncated or improperly formatted content. An attacker able to supply a
specially crafted hive file to an application using the hivex library could
possibly use this flaw to execute arbitrary code with the privileges of the
user running that application. (CVE-2014-9273)

Red Hat would like to thank Mahmoud Al-Qudsi of NeoSmart Technologies for
reporting this issue.

This update also fixes the following bug:

  * The hivex(3) man page previously contained a typographical error. This
update fixes the typo. (BZ#1164693)

All hivex users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"hivex on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1378-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00026.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"hivex", rpm:"hivex~1.3.3~4.3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hivex-debuginfo", rpm:"hivex-debuginfo~1.3.3~4.3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-hivex", rpm:"perl-hivex~1.3.3~4.3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
