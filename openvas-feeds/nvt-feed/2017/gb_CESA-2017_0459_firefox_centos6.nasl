# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882677");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-09 05:01:26 +0100 (Thu, 09 Mar 2017)");
  script_cve_id("CVE-2017-5398", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402",
                "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5407", "CVE-2017-5408",
                "CVE-2017-5410");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:05:00 +0000 (Wed, 01 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2017:0459 centos6");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 45.8.0 ESR.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2017-5398, CVE-2017-5400, CVE-2017-5401, CVE-2017-5402,
CVE-2017-5404, CVE-2017-5407, CVE-2017-5408, CVE-2017-5410, CVE-2017-5405)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Nils, Jerri Rice, Rh0, Anton Eliasson, David
Kohlbrenner, Ivan Fratric of Google Project Zero, Anonymous, Eric Lawrence
of Chrome Security, Boris Zbarsky, Christian Holler, Honza Bambas, Jon
Coppeard, Randell Jesup, Andre Bargull, Kan-Ru Chen, and Nathan Froyd as
the original reporters.");
  script_tag(name:"affected", value:"firefox on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:0459");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-March/022327.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~45.8.0~2.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
