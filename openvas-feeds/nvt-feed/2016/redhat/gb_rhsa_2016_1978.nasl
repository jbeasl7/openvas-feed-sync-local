# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871666");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-10-05 15:43:08 +0530 (Wed, 05 Oct 2016)");
  script_cve_id("CVE-2016-1000111");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-13 20:04:00 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for python-twisted-web RHSA-2016:1978-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-twisted-web'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Twisted is an event-based framework for
internet applications. Twisted Web is a complete web server, aimed at hosting
web applications using Twisted and Python, but fully able to serve static pages too.

Security Fix(es):

  * It was discovered that python-twisted-web used the value of the Proxy
header from HTTP requests to initialize the HTTP_PROXY environment variable
for CGI scripts, which in turn was incorrectly used by certain HTTP client
implementations to configure the proxy for outgoing HTTP requests. A remote
attacker could possibly use this flaw to redirect HTTP requests performed
by a CGI script to an attacker-controlled proxy via a malicious HTTP
request. (CVE-2016-1000111)

Note: After this update, python-twisted-web will no longer pass the value
of the Proxy request header to scripts via the HTTP_PROXY environment
variable.

Red Hat would like to thank Scott Geary (VendHQ) for reporting this issue.");
  script_tag(name:"affected", value:"python-twisted-web on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:1978-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-September/msg00039.html");
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

  if ((res = isrpmvuln(pkg:"python-twisted-web", rpm:"python-twisted-web~8.2.0~5.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
