# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871620");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-06-03 16:25:10 +0530 (Fri, 03 Jun 2016)");
  script_cve_id("CVE-2015-2328", "CVE-2015-3217", "CVE-2015-5073", "CVE-2015-8385",
                "CVE-2015-8386", "CVE-2015-8388", "CVE-2015-8391", "CVE-2016-3191");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 17:29:00 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for pcre RHSA-2016:1025-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcre'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"PCRE is a Perl-compatible regular expression
library.

Security Fix(es):

  * Multiple flaws were found in the way PCRE handled malformed regular
expressions. An attacker able to make an application using PCRE process a
specially crafted regular expression could use these flaws to cause the
application to crash or, possibly, execute arbitrary code. (CVE-2015-8385,
CVE-2016-3191, CVE-2015-2328, CVE-2015-3217, CVE-2015-5073, CVE-2015-8388,
CVE-2015-8391, CVE-2015-8386)");
  script_tag(name:"affected", value:"pcre on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:1025-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-May/msg00025.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"pcre", rpm:"pcre~8.32~15.el7_2.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcre-debuginfo", rpm:"pcre-debuginfo~8.32~15.el7_2.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcre-devel", rpm:"pcre-devel~8.32~15.el7_2.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
