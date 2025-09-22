# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55037");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 773-1 (several)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20773-1");
  script_tag(name:"insight", value:"This advisory adds security support for the stable amd64 distribution.
It covers all security updates since the release of sarge, which were
missing updated packages for the not yet official amd64 port.  Future
security advisories will include updates for this port as well.");
  script_tag(name:"summary", value:"The remote host is missing an update to several
announced via advisory DSA 773-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"affix", ver:"2.1.1-2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libaffix-dev", ver:"2.1.1-2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libaffix2", ver:"2.1.1-2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"centericq", ver:"4.20.0-1sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"centericq-common", ver:"4.20.0-1sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"centericq-fribidi", ver:"4.20.0-1sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"centericq-utf8", ver:"4.20.0-1sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav", ver:"0.84-2.sarge.1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.84-2.sarge.1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.84-2.sarge.1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"clamav-milter", ver:"0.84-2.sarge.1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.84-2.sarge.1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libclamav1", ver:"0.84-2.sarge.1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"crip", ver:"3.5-1sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cvs", ver:"1.11.1p1debian-11", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcpcd", ver:"1.3.22pl4-21sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ekg", ver:"1.5+20050411-5", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgadu-dev", ver:"1.5+20050411-5", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgadu3", ver:"1.5+20050411-5", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ettercap", ver:"0.7.1-1sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ettercap-common", ver:"0.7.1-1sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ettercap-gtk", ver:"0.7.1-1sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"fuse-utils", ver:"2.2.1-4sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfuse-dev", ver:"2.2.1-4sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfuse2", ver:"2.2.1-4sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gaim", ver:"1.2.1-1.4", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gaim-dev", ver:"1.2.1-1.4", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gedit", ver:"2.8.3-4sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gopher", ver:"3.0.7sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heartbeat", ver:"1.2.3-9sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heartbeat-dev", ver:"1.2.3-9sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpils-dev", ver:"1.2.3-9sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpils0", ver:"1.2.3-9sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstonith-dev", ver:"1.2.3-9sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstonith0", ver:"1.2.3-9sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"stonith", ver:"1.2.3-9sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-clients", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-clients-x", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-dev", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-kdc", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-servers", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"heimdal-servers-x", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libasn1-6-heimdal", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi1-heimdal", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libhdb7-heimdal", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt4-heimdal", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv7-heimdal", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-17-heimdal", ver:"0.6.3-10sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ht", ver:"0.8.0-2sarge4", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.3.6-2sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.3.6-2sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.3.6-2sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.3.6-2sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.3.6-2sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.3.6-2sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.3.6-2sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm55", ver:"1.3.6-2sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.3.6-2sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb53", ver:"1.3.6-2sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-geo", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-ldap", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-mysql", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-pgsql", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-pipe", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-backend-sqlite", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-recursor", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pdns-server", ver:"2.9.17-13sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppxp", ver:"0.2001080415-10sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppxp-dev", ver:"0.2001080415-10sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppxp-tcltk", ver:"0.2001080415-10sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppxp-x11", ver:"0.2001080415-10sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qpopper", ver:"4.0.5-4sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qpopper-drac", ver:"4.0.5-4sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"razor", ver:"2.670-1sarge2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libdbm-ruby1.8", ver:"1.8.2-7sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgdbm-ruby1.8", ver:"1.8.2-7sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenssl-ruby1.8", ver:"1.8.2-7sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libreadline-ruby1.8", ver:"1.8.2-7sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.2-7sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.2-7sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.2-7sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.2-7sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.2-7sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"spamc", ver:"3.0.3-2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sudo", ver:"1.6.8p7-1.1sarge1", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-bin", ver:"1.2.2-4.sarge.2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib1g", ver:"1.2.2-4.sarge.2", rls:"DEB3.1")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib1g-dev", ver:"1.2.2-4.sarge.2", rls:"DEB3.1")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
