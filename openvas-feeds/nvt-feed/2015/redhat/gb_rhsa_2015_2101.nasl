# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871501");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-11-20 06:24:47 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2014-4616", "CVE-2014-4650",
                "CVE-2014-7185", "CVE-2014-9365");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 13:49:00 +0000 (Wed, 26 Feb 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for python RHSA-2015:2101-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Python is an interpreted, interactive,
object-oriented programming language often compared to Tcl, Perl, Scheme, or
Java. Python includes modules, classes, exceptions, very high level dynamic
data types and dynamic typing. Python supports interfaces to many system calls
and libraries, as well as to various windowing systems (X11, Motif, Tk, Mac and
MFC).

It was discovered that the Python xmlrpclib module did not restrict the
size of gzip-compressed HTTP responses. A malicious XMLRPC server could
cause an XMLRPC client using xmlrpclib to consume an excessive amount of
memory. (CVE-2013-1753)

It was discovered that multiple Python standard library modules
implementing network protocols (such as httplib or smtplib) failed to
restrict the sizes of server responses. A malicious server could cause a
client using one of the affected modules to consume an excessive amount of
memory. (CVE-2013-1752)

It was discovered that the CGIHTTPServer module incorrectly handled URL
encoded paths. A remote attacker could use this flaw to execute scripts
outside of the cgi-bin directory, or disclose the source code of the
scripts in the cgi-bin directory. (CVE-2014-4650)

An integer overflow flaw was found in the way the buffer() function handled
its offset and size arguments. An attacker able to control these arguments
could use this flaw to disclose portions of the application memory or cause
it to crash. (CVE-2014-7185)

A flaw was found in the way the json module handled negative index
arguments passed to certain functions (such as raw_decode()). An attacker
able to control the index value passed to one of the affected functions
could possibly use this flaw to disclose portions of the application
memory. (CVE-2014-4616)

The Python standard library HTTP client modules (such as httplib or urllib)
did not perform verification of TLS/SSL certificates when connecting to
HTTPS servers. A man-in-the-middle attacker could use this flaw to hijack
connections and eavesdrop or modify transferred data. (CVE-2014-9365)

Note: The Python standard library was updated to make it possible to enable
certificate verification by default. However, for backwards compatibility,
verification remains disabled by default. Future updates may change this
default. Refer to the Knowledgebase article 2039753 linked to in the
References section for further details about this change. (BZ#1219108)

This update also fixes the following bugs:

  * Subprocesses used with the Eventlet library or regular threads previously
tried to close epoll file descriptors twice, which led to an 'Invalid
argument' error. Subprocesses h ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"python on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2101-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00019.html");
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

  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.7.5~34.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.7.5~34.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.5~34.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.7.5~34.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
