# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53804");
  script_cve_id("CVE-2001-0568", "CVE-2001-0569");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Debian Security Advisory DSA 043-1 (zope)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20043-1");
  script_tag(name:"insight", value:"This advisory covers several vulnerabilities in Zope that have been
addressed.

1. Hotfix 08_09_2000 'Zope security alert and hotfix product'

The issue involves the fact that the getRoles method of user objects
contained in the default UserFolder implementation returns a mutable
Python type.  Because the mutable object is still associated with
the persistent User object, users with the ability to edit DTML
could arrange to give themselves extra roles for the duration of a
single request by mutating the roles list as a part of the request
processing.

2. Hotfix 2000-10-02 'ZPublisher security update'

It is sometimes possible to access, through an URL only, objects
protected by a role which the user has in some context, but not in
the context of the accessed object.

3. Hotfix 2000-10-11 'ObjectManager subscripting'

The issue involves the fact that the 'subscript notation' that can
be used to access items of ObjectManagers (Folders) did not
correctly restrict return values to only actual sub items.  This
made it possible to access names that should be private from DTML
(objects with names beginning with the underscore '_' character).
This could allow DTML authors to see private implementation data
structures and in certain cases possibly call methods that they
shouldn't have access to from DTML.

4. Hotfix 2001-02-23 'Class attribute access'

The issue is related to ZClasses in that a user with through-the-web
scripting capabilities on a Zope site can view and assign class
attributes to ZClasses, possibly allowing them to make inappropriate
changes to ZClass instances.

A second part fixes problems in the ObjectManager, PropertyManager,
and PropertySheet classes related to mutability of method return
values which could be perceived as a security problem.

We recommend you upgrade your zope package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to zope
announced via advisory DSA 043-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"zope", ver:"2.1.6-7", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
