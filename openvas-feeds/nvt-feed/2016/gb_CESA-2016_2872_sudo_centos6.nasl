# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882609");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-08 05:33:25 +0100 (Thu, 08 Dec 2016)");
  script_cve_id("CVE-2016-7032", "CVE-2016-7076");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-30 18:15:00 +0000 (Wed, 30 Sep 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for sudo CESA-2016:2872 centos6");
  script_tag(name:"summary", value:"Check the version of sudo");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The sudo packages contain the sudo utility
which allows system administrators to provide certain users with the permission
to execute privileged commands, which are used for system management purposes,
without having to log in as root.

Security Fix(es):

  * It was discovered that the sudo noexec restriction could have been
bypassed if application run via sudo executed system(), popen(), or
wordexp() C library functions with a user supplied argument. A local user
permitted to run such application via sudo with noexec restriction could
use these flaws to execute arbitrary commands with elevated privileges.
(CVE-2016-7032, CVE-2016-7076)

These issues were discovered by Florian Weimer (Red Hat).");
  script_tag(name:"affected", value:"sudo on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:2872");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-December/022171.html");
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

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.6p3~25.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.8.6p3~25.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
