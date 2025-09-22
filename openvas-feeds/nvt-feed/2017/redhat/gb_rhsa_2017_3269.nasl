# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812315");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-11-30 07:33:14 +0100 (Thu, 30 Nov 2017)");
  script_cve_id("CVE-2017-16844");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for procmail RHSA-2017:3269-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'procmail'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The procmail packages contain a mail
  processing tool that can be used to create mail servers, mailing lists, sort
  incoming mail into separate folders or files, preprocess mail, start any program
  upon mail arrival, or automatically forward selected incoming mail. Security
  Fix(es): * A heap-based buffer overflow flaw was found in procmail's formail
  utility. A remote attacker could send a specially crafted email that, when
  processed by formail, could cause formail to crash or, possibly, execute
  arbitrary code as the user running formail. (CVE-2017-16844)");
  script_tag(name:"affected", value:"procmail on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:3269-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-November/msg00037.html");
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

  if ((res = isrpmvuln(pkg:"procmail", rpm:"procmail~3.22~36.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"procmail-debuginfo", rpm:"procmail-debuginfo~3.22~36.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
