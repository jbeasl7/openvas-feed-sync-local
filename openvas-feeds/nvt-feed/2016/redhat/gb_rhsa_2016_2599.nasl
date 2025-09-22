# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871701");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-11-04 05:42:30 +0100 (Fri, 04 Nov 2016)");
  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5351", "CVE-2016-0706",
                "CVE-2016-0714", "CVE-2016-0763", "CVE-2016-3092");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-17 08:15:00 +0000 (Sat, 17 Jul 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for tomcat RHSA-2016:2599-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Apache Tomcat is a servlet container for
the Java Servlet and JavaServer Pages (JSP) technologies.

The following packages have been upgraded to a newer upstream version:
tomcat (7.0.69). (BZ#1287928)

Security Fix(es):

  * A CSRF flaw was found in Tomcat's the index pages for the Manager and
Host Manager applications. These applications included a valid CSRF token
when issuing a redirect as a result of an unauthenticated request to the
root of the web application. This token could then be used by an attacker
to perform a CSRF attack. (CVE-2015-5351)

  * It was found that several Tomcat session persistence mechanisms could
allow a remote, authenticated user to bypass intended SecurityManager
restrictions and execute arbitrary code in a privileged context via a web
application that placed a crafted object in a session. (CVE-2016-0714)

  * A security manager bypass flaw was found in Tomcat that could allow
remote, authenticated users to access arbitrary application data,
potentially resulting in a denial of service. (CVE-2016-0763)

  * A denial of service vulnerability was identified in Commons FileUpload
that occurred when the length of the multipart boundary was just below the
size of the buffer (4096 bytes) used to read the uploaded file if the
boundary was the typical tens of bytes long. (CVE-2016-3092)

  * A directory traversal flaw was found in Tomcat's RequestUtil.java. A
remote, authenticated user could use this flaw to bypass intended
SecurityManager restrictions and list a parent directory via a '/..' in a
pathname used by a web application in a getResource, getResourceAsStream,
or getResourcePaths call. (CVE-2015-5174)

  * It was found that Tomcat could reveal the presence of a directory even
when that directory was protected by a security constraint. A user could
make a request to a directory via a URL not ending with a slash and,
depending on whether Tomcat redirected that request, could confirm whether
that directory existed. (CVE-2015-5345)

  * It was found that Tomcat allowed the StatusManagerServlet to be loaded by
a web application when a security manager was configured. This allowed a
web application to list all deployed web applications and expose sensitive
information such as session IDs. (CVE-2016-0706)

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"tomcat on
  Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:2599-02");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-November/msg00035.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~7.0.69~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~7.0.69~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-el-2.2-api", rpm:"tomcat-el-2.2-api~7.0.69~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-jsp-2.2-api", rpm:"tomcat-jsp-2.2-api~7.0.69~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~7.0.69~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-servlet-3.0-api", rpm:"tomcat-servlet-3.0-api~7.0.69~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~7.0.69~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
