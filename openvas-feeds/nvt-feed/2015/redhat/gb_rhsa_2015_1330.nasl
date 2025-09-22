# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871404");
  script_version("2024-03-21T05:06:54+0000");
  script_cve_id("CVE-2013-1752", "CVE-2014-1912", "CVE-2014-4650", "CVE-2014-7185");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 13:49:00 +0000 (Wed, 26 Feb 2020)");
  script_tag(name:"creation_date", value:"2015-07-23 06:25:42 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for python RHSA-2015:1330-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Python is an interpreted, interactive, object-oriented programming language
often compared to Tcl, Perl, Scheme, or Java. Python includes modules,
classes, exceptions, very high level dynamic data types and dynamic typing.
Python supports interfaces to many system calls and libraries, as well as
to various windowing systems (X11, Motif, Tk, Mac and MFC).

It was discovered that the socket.recvfrom_into() function failed to check
the size of the supplied buffer. This could lead to a buffer overflow when
the function was called with an insufficiently sized buffer.
(CVE-2014-1912)

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

These updated python packages also include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. For information on the most significant of these changes, users
are directed to the referenced article on the Red Hat Customer Portal.

All python users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add this
enhancement.");
  script_tag(name:"affected", value:"python on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1330-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00023.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  script_xref(name:"URL", value:"https://access.redhat.com/articles/1495363");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.6.6~64.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.6.6~64.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.6.6~64.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.6.6~64.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.6.6~64.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
