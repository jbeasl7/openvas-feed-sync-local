# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61861");
  script_cve_id("CVE-2008-4989");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 03:19:21 +0000 (Fri, 09 Feb 2024)");

  script_name("Slackware: Security Advisory (SSA:2008-315-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.0|12\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2008-315-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.465317");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SSA:2008-315-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New gnutls packages are available for Slackware 12.0, 12.1, and -current to
fix a security issue.

NOTE: The package for 12.0 has a different shared library soname, and the
packages for 12.1 and -current have an API/ABI change. Only the Pidgin package
in Slackware links with GnuTLS, and upgraded Pidgin packages have also been
made available. However, if the updated GnuTLS package is installed any other
custom-compiled software that uses GnuTLS may need to be recompiled.

More details about this issue will become available in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]


Here are the details from the Slackware 12.1 ChangeLog:
+--------------------------+
patches/packages/gnutls-2.6.1-i486-1_slack12.1.tgz:
 Upgraded to gnutls-2.6.1.
 From the gnutls-2.6.1 NEWS file:
 ** libgnutls: Fix X.509 certificate chain validation error.
 [GNUTLS-SA-2008-3] The flaw makes it possible for man in the middle
 attackers (i.e., active attackers) to assume any name and trick GNU TLS
 clients into trusting that name. Thanks for report and analysis from
 Martin von Gagern <Martin.vGagern@gmx.net>. [CVE-2008-4989]
 For more information, see:
 [link moved to references]
 IMPORTANT NOTE: This update modifies the API and ABI for the
 gnutls_pk_params_st function. Any software that uses the function will
 need to be recompiled.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'gnutls' package(s) on Slackware 12.0, Slackware 12.1, Slackware current.");

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

if(release == "SLK12.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"2.6.1-i486-1_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"2.6.1-i486-1_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnutls", ver:"2.6.1-i486-1", rls:"SLKcurrent"))) {
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
