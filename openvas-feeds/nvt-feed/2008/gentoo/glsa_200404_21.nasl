# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54560");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Gentoo Security Advisory GLSA 200404-21 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"There is a bug in smbfs which may allow local users to gain root via a
setuid file on a mounted Samba share. Also, there is a tmpfile symlink
vulnerability in the smbprint script distributed with Samba.");
  script_tag(name:"solution", value:"All users should update to the latest version of the Samba package.

The following commands will perform the upgrade:

    # emerge sync

    # emerge -pv '>=net-fs/samba-3.0.2a-r2'
    # emerge '>=net-fs/samba-3.0.2a-r2'

Those who are using Samba's password database also need to run the
following command:

    # pdbedit --force-initialized-passwords

Those using LDAP for Samba passwords also need to check the
sambaPwdLastSet attribute on each account, and ensure it is not 0.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200404-21");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=41800");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=45965");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/353222/2004-04-09/2004-04-15/1");
  script_xref(name:"URL", value:"http://seclists.org/lists/bugtraq/2004/Mar/0189.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200404-21.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-fs/samba", unaffected: make_list("ge 3.0.2a-r2"), vulnerable: make_list("le 3.0.2a"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
