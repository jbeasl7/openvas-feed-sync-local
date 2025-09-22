# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882794");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-10-27 14:31:55 +0200 (Fri, 27 Oct 2017)");
  script_cve_id("CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6464");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-24 11:29:00 +0000 (Thu, 24 Jan 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for ntp CESA-2017:3071 centos6");
  script_tag(name:"summary", value:"Check the version of ntp");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Network Time Protocol (NTP) is used to
synchronize a computer's time with another referenced time source. These packages
include the ntpd service which continuously adjusts system time and utilities
used to query and configure the ntpd service.

Security Fix(es):

  * Two vulnerabilities were discovered in the NTP server's parsing of
configuration directives. A remote, authenticated attacker could cause ntpd
to crash by sending a crafted message. (CVE-2017-6463, CVE-2017-6464)

  * A vulnerability was found in NTP, in the parsing of packets from the
/dev/datum device. A malicious device could send crafted messages, causing
ntpd to crash. (CVE-2017-6462)

Red Hat would like to thank the NTP project for reporting these issues.
Upstream acknowledges Cure53 as the original reporter of these issues.");
  script_tag(name:"affected", value:"ntp on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:3071");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-October/022608.html");
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

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~12.el6.centos.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~12.el6.centos.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~12.el6.centos.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.6p5~12.el6.centos.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
