# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017366.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881368");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:36:51 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-1018");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:0324");
  script_name("CentOS Update for logwatch CESA-2011:0324 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'logwatch'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"logwatch on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Logwatch is a customizable log analysis system. Logwatch parses through
  your system's logs for a given period of time and creates a report
  analyzing areas that you specify, in as much detail as you require.

  A flaw was found in the way Logwatch processed log files. If an attacker
  were able to create a log file with a malicious file name, it could result
  in arbitrary code execution with the privileges of the root user when that
  log file is analyzed by Logwatch. (CVE-2011-1018)

  Users of logwatch should upgrade to this updated package, which contains a
  backported patch to resolve this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"logwatch", rpm:"logwatch~7.3~9.el5_6", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
