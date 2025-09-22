# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53897");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2003-141-05)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK9\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2003-141-05");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.301438");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_ssl' package(s) announced via the SSA:2003-141-05 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An upgrade for mod_ssl to version 2.8.14_1.3.27 is now available.
This version provides RSA blinding by default which prevents an
extended timing analysis from revealing details of the secret key
to an attacker. Note that this problem was already fixed within
OpenSSL, so this is a 'double fix'. With this package, mod_ssl
is secured even if OpenSSL is not.

We recommend sites using mod_ssl upgrade to this new package.


Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
Tue May 20 20:13:09 PDT 2003
patches/packages/mod_ssl-2.8.14_1.3.27-i386-1.tgz: Upgraded to
 mod_ssl-2.8.14_1.3.27. Includes RSA blinding fixes.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'mod_ssl' package(s) on Slackware 9.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK9.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.14_1.3.27-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
