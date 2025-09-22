# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53817");
  script_cve_id("CVE-2001-1162");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 065-1 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20065-1");
  script_tag(name:"insight", value:"Michal Zalewski discovered that samba does not properly validate
NetBIOS names from remote machines.

By itself that is not a problem, except if Samba is configure to
write log-files to a file that includes the NetBIOS name of the
remote side by using the `%m' macro in the `log file' command. In
that case an attacker could use a NetBIOS name like '../tmp/evil'.
If the log-file was set to '/var/log/samba/%s' samba would them
write to /var/tmp/evil.

Since the NetBIOS name is limited to 15 characters and the `log
file' command could have an extension to the filename the results
of this are limited. However if the attacker is also able to create
symbolic links on the samba server he could trick samba into
appending any data he wants to all files on the filesystem which
samba can write to.

The Debian GNU/Linux packaged version of samba has a safe
configuration and is not vulnerable.

As temporary workaround for systems that are vulnerable change all
occurrences of the `%m' macro in smb.conf to `%l' and restart samba.

This has been fixed in version 2.0.7-3.4, and we recommend that up
upgrade your samba package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to samba
announced via advisory DSA 065-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"samba-doc", ver:"2.0.7-3.4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"2.0.7-3.4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba", ver:"2.0.7-3.4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbclient", ver:"2.0.7-3.4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbfs", ver:"2.0.7-3.4", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"swat", ver:"2.0.7-3.4", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
