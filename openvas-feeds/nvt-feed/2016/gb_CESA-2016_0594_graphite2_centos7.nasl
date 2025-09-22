# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882448");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-11 12:47:16 +0530 (Mon, 11 Apr 2016)");
  script_cve_id("CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1526");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for graphite2 CESA-2016:0594 centos7");
  script_tag(name:"summary", value:"Check the version of graphite2");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Graphite2 is a project within SIL's
Non-Roman Script Initiative and Language Software Development groups to provide
rendering capabilities for complex non-Roman writing systems. Graphite can be
used to create 'smart fonts' capable of displaying writing systems with various
complex behaviors. With respect to the Text Encoding Model, Graphite handles the
'Rendering' aspect of writing system implementation.

The following packages have been upgraded to a newer upstream version:
graphite2 (1.3.6).

Security Fix(es):

  * Various vulnerabilities have been discovered in Graphite2. An attacker
able to trick an unsuspecting user into opening specially crafted font
files in an application using Graphite2 could exploit these flaws to cause
the application to crash or, potentially, execute arbitrary code with the
privileges of the application. (CVE-2016-1521, CVE-2016-1522,
CVE-2016-1523, CVE-2016-1526)");
  script_tag(name:"affected", value:"graphite2 on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:0594");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-April/021811.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"graphite2", rpm:"graphite2~1.3.6~1.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"graphite2-devel", rpm:"graphite2-devel~1.3.6~1.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
