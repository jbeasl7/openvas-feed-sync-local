# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871416");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-08-03 15:08:00 +0530 (Mon, 03 Aug 2015)");
  script_cve_id("CVE-2015-3245", "CVE-2015-3246");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for libuser RHSA-2015:1483-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libuser'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libuser library implements a standardized interface for manipulating
and administering user and group accounts. Sample applications that are
modeled after applications from the shadow password suite (shadow-utils)
are included in these packages.

Two flaws were found in the way the libuser library handled the /etc/passwd
file. A local attacker could use an application compiled against libuser
(for example, userhelper) to manipulate the /etc/passwd file, which could
result in a denial of service or possibly allow the attacker to escalate
their privileges to root. (CVE-2015-3245, CVE-2015-3246)

Red Hat would like to thank Qualys for reporting these issues.

All libuser users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue.");
  script_tag(name:"affected", value:"libuser on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1483-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00043.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"libuser", rpm:"libuser~0.60~7.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuser-debuginfo", rpm:"libuser-debuginfo~0.60~7.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuser-python", rpm:"libuser-python~0.60~7.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}