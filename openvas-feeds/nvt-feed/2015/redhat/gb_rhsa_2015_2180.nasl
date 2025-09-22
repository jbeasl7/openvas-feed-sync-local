# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871495");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-11-20 06:23:12 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2013-0334");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for rubygem-bundler and rubygem-thor RHSA-2015:2180-07");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-bundler and rubygem-thor'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Bundler manages an application's
dependencies through its entire life, across many machines, systematically and
repeatably. Thor is a toolkit for building powerful command-line interfaces.

A flaw was found in the way Bundler handled gems available from multiple
sources. An attacker with access to one of the sources could create a
malicious gem with the same name, which they could then use to trick a user
into installing, potentially resulting in execution of code from the
attacker-supplied malicious gem. (CVE-2013-0334)

Bundler has been upgraded to upstream version 1.7.8 and Thor has been
upgraded to upstream version 1.19.1, both of which provide a number of bug
fixes and enhancements over the previous versions. (BZ#1194243, BZ#1209921)

All rubygem-bundler and rubygem-thor users are advised to upgrade to these
updated packages, which correct these issues and add these enhancements.");
  script_tag(name:"affected", value:"rubygem-bundler and rubygem-thor on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2180-07");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00029.html");
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

  if ((res = isrpmvuln(pkg:"rubygem-bundler", rpm:"rubygem-bundler~1.7.8~3.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-thor", rpm:"rubygem-thor~0.19.1~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
