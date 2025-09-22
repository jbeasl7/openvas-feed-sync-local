# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882508");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-22 05:28:52 +0200 (Wed, 22 Jun 2016)");
  script_cve_id("CVE-2016-4444", "CVE-2016-4445", "CVE-2016-4446", "CVE-2016-4989");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-17 12:47:00 +0000 (Mon, 17 Apr 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for setroubleshoot-plugins CESA-2016:1267 centos6");
  script_tag(name:"summary", value:"Check the version of setroubleshoot-plugins");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The setroubleshoot packages provide tools to help diagnose SELinux
problems. When Access Vector Cache (AVC) messages are returned, an alert
can be generated that provides information about the problem and helps to
track its resolution.

The setroubleshoot-plugins package provides a set of analysis plugins for
use with setroubleshoot. Each plugin has the capacity to analyze SELinux
AVC data and system data to provide user friendly reports describing how to
interpret SELinux AVC denials.

Security Fix(es):

  * Shell command injection flaws were found in the way the setroubleshoot
executed external commands. A local attacker able to trigger certain
SELinux denials could use these flaws to execute arbitrary code with root
privileges. (CVE-2016-4445, CVE-2016-4989)

  * Shell command injection flaws were found in the way the setroubleshoot
allow_execmod and allow_execstack plugins executed external commands. A
local attacker able to trigger an execmod or execstack SELinux denial could
use these flaws to execute arbitrary code with root privileges.
(CVE-2016-4444, CVE-2016-4446)

The CVE-2016-4444 and CVE-2016-4446 issues were discovered by Milos Malik
(Red Hat) and the CVE-2016-4445 and CVE-2016-4989 issues were discovered by
Red Hat Product Security.");
  script_tag(name:"affected", value:"setroubleshoot-plugins on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:1267");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-June/021913.html");
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

  if ((res = isrpmvuln(pkg:"setroubleshoot-plugins", rpm:"setroubleshoot-plugins~3.0.40~3.1.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
