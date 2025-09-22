# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54529");
  script_cve_id("CVE-2004-0113");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200403-04 (Apache)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A memory leak in mod_ssl allows a remote denial of service attack against
an SSL-enabled server via plain HTTP requests. Another flaw was found when
arbitrary client-supplied strings can be written to the error log,
allowing the exploit of certain terminal emulators. A third flaw exists
with the mod_disk_cache module.");
  script_tag(name:"solution", value:"Users are urged to upgrade to Apache 2.0.49:

    # emerge sync
    # emerge -pv '>=net-www/apache-2.0.49'
    # emerge '>=net-www/apache-2.0.49'

    # ** IMPORTANT **

    # If you are migrating from Apache 2.0.48-r1 or earlier versions,
    # it is important that the following directories are removed.

    # The following commands should cause no data loss since these
    # are symbolic links.

    # rm /etc/apache2/lib /etc/apache2/logs /etc/apache2/modules
    # rm /etc/apache2/extramodules

    # ** ** ** ** **

    # ** ALSO NOTE **

    # Users who use mod_disk_cache should edit their Apache
    # configuration and disable mod_disk_cache.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200403-04");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=45206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9933");
  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/Announcement2.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200403-04.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/apache", unaffected: make_list("eq 1.3*", "ge 2.0.49"), vulnerable: make_list("le 2.0.48"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
