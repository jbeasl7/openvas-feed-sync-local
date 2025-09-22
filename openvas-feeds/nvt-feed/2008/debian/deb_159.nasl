# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53730");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1119");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 159-2 (python)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20159-2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5581");
  script_tag(name:"insight", value:"The bugfix we distributed in DSA 159-1 unfortunately caused Python to
sometimes behave improperly when a non-executable file existed earlier
in the path and an executable file of the same name existed later in
the path.  Zack Weinberg fixed this in the Python source.  For
reference, here's the original advisory text:

Zack Weinberg discovered an insecure use of a temporary file in
os._execvpe from os.py. It uses a predictable name which could
lead execution of arbitrary code.

This problem has been fixed in several versions of Python: For the
current stable distribution (woody) it has been fixed in version
1.5.2-23.2 of Python 1.5, in version 2.1.3-3.2 of Python 2.1 and in
version 2.2.1-4.2 of Python 2.2. For the old stable distribution
(potato) this has been fixed in version 1.5.2-10potato13 for Python
1.5. For the unstable distribution (sid) this has been fixed in
version 1.5.2-25 of Python 1.5, in version 2.1.3-9 of Python 2.1 and
in version 2.2.1-11 of Python 2.2. Python 2.3 is not affected by the
original problem.");

  script_tag(name:"solution", value:"We recommend that you upgrade your Python packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to python
announced via advisory DSA 159-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"python-base", ver:"1.5.2-10potato13", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python1.5", ver:"1.5.2-23.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python2.1", ver:"2.1.3-3.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python2.2", ver:"2.2.1-4.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
