# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-August/msg00026.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870815");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-08-28 10:25:44 +0530 (Tue, 28 Aug 2012)");
  script_cve_id("CVE-2012-0878");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2012:1206-01");
  script_name("RedHat Update for python-paste-script RHSA-2012:1206-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-paste-script'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"python-paste-script on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Python Paste provides middleware for building and running Python web
  applications. The python-paste-script package includes paster, a tool for
  working with and running Python Paste applications.

  It was discovered that paster did not drop supplementary group privileges
  when started by the root user. Running 'paster serve' as root to start a
  Python web application that will run as a non-root user and group resulted
  in that application running with root group privileges. This could possibly
  allow a remote attacker to gain access to files that should not be
  accessible to the application. (CVE-2012-0878)

  All paster users should upgrade to this updated package, which contains a
  backported patch to resolve this issue. All running paster instances
  configured to drop privileges must be restarted for this update to take
  effect.");
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

  if ((res = isrpmvuln(pkg:"python-paste-script", rpm:"python-paste-script~1.7.3~5.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
