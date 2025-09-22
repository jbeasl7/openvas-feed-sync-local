# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871584");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-03-23 06:17:05 +0100 (Wed, 23 Mar 2016)");
  script_cve_id("CVE-2010-5325", "CVE-2015-8327", "CVE-2015-8560");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for foomatic RHSA-2016:0491-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'foomatic'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Foomatic is a comprehensive,
spooler-independent database of printers, printer drivers, and driver descriptions.
The package also includes spooler-independent command line interfaces to manipulate
queues and to print files and manipulate print jobs.

It was discovered that the unhtmlify() function of foomatic-rip did not
correctly calculate buffer sizes, possibly leading to a heap-based memory
corruption. A malicious attacker could exploit this flaw to cause
foomatic-rip to crash or, possibly, execute arbitrary code.
(CVE-2010-5325)

It was discovered that foomatic-rip failed to remove all shell special
characters from inputs used to construct command lines for external
programs run by the filter. An attacker could possibly use this flaw to
execute arbitrary commands. (CVE-2015-8327, CVE-2015-8560)

All foomatic users should upgrade to this updated package, which contains
backported patches to correct these issues.");
  script_tag(name:"affected", value:"foomatic on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:0491-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-March/msg00056.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"foomatic", rpm:"foomatic~4.0.4~5.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"foomatic-debuginfo", rpm:"foomatic-debuginfo~4.0.4~5.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
