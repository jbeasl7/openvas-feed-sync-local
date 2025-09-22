# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65144");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-10 16:11:46 +0200 (Sat, 10 Oct 2009)");
  script_cve_id("CVE-2007-2727", "CVE-2007-3472", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478", "CVE-2007-3799");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SLES9: Security update for PHP4");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=SLES9\.0");
  script_tag(name:"solution", value:"Please install the updates provided by SuSE.");
  script_tag(name:"summary", value:"The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    php4-imap
    php4-readline
    php4-iconv
    php4-servlet
    apache2-mod_php4
    php4-gd
    php4-sysvshm
    php4-pear
    php4-xslt
    php4-zlib
    php4-mcal
    php4-yp
    php4-wddx
    mod_php4
    mod_php4-apache2
    php4-ftp
    php4-swf
    php4-mime_magic
    php4-filepro
    php4-bcmath
    php4-exif
    php4-curl
    php4-sysvsem
    php4-mhash
    php4-fastcgi
    php4-sockets
    php4-shmop
    php4-unixODBC
    php4-mbstring
    php4-mysql
    php4-calendar
    php4
    php4-domxml
    php4-devel
    mod_php4-servlet
    apache-mod_php4
    php4-gettext
    php4-session
    php4-ldap
    php4-ctype
    mod_php4-core
    php4-recode
    php4-pgsql
    php4-dba
    php4-qtdom
    php4-gmp
    php4-bz2
    php4-dbase
    php4-mcrypt
    php4-snmp

For more information, please visit the referenced security
advisories.

More details may also be found by searching for keyword
5015608 within the SuSE Enterprise Server 9 patch
database linked in the references.");

  script_xref(name:"URL", value:"http://download.novell.com/patch/finder/");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"php4-imap", rpm:"php4-imap~4.3.4~43.82", rls:"SLES9.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
