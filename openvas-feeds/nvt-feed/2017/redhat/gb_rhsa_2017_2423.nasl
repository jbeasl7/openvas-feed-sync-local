# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871877");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-08-08 07:19:05 +0200 (Tue, 08 Aug 2017)");
  script_cve_id("CVE-2017-5645");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-31 17:37:00 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for log4j RHSA-2017:2423-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'log4j'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Log4j is a tool to help the programmer
output log statements to a variety of output targets.

Security Fix(es):

  * It was found that when using remote logging with log4j socket server the
log4j server would deserialize any log event received via TCP or UDP. An
attacker could use this flaw to send a specially crafted log event that,
during deserialization, would execute arbitrary code in the context of the
logger application. (CVE-2017-5645)");
  script_tag(name:"affected", value:"log4j on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:2423-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00038.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"log4j", rpm:"log4j~1.2.17~16.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
