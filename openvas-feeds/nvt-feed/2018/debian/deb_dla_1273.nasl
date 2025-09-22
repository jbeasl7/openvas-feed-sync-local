# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891273");
  script_cve_id("CVE-2017-18121", "CVE-2017-18122", "CVE-2018-6521");
  script_tag(name:"creation_date", value:"2018-02-20 23:00:00 +0000 (Tue, 20 Feb 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-15 16:36:21 +0000 (Thu, 15 Feb 2018)");

  script_name("Debian: Security Advisory (DLA-1273-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1273-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1273-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'simplesamlphp' package(s) announced via the DLA-1273-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"simplesamlphp, an authentication and federation application has been found vulnerable to Cross Site Scripting (XSS), signature validation byepass and using insecure connection charset.

CVE-2017-18121

A Cross Site Scripting (XSS) issue has been found in the consentAdmin module of SimpleSAMLphp through 1.14.15, allowing an attacker to manually craft links that a victim can open, executing arbitrary javascript code.

CVE-2017-18122

A signature-validation bypass issue was discovered in SimpleSAMLphp through 1.14.16. Service Provider using SAML 1.1 will regard as valid any unsigned SAML response containing more than one signed assertion, provided that the signature of at least one of the assertions is valid. Attributes contained in all the assertions received will be merged and the entityID of the first assertion received will be used, allowing an attacker to impersonate any user of any IdP given an assertion signed by the targeted IdP.

CVE-2018-6521

The sqlauth module in SimpleSAMLphp before 1.15.2 relies on the MySQL utf8 charset, which truncates queries upon encountering four-byte characters. There might be a scenario in which this allows remote attackers to bypass intended access restrictions.

For Debian 7 Wheezy, these problems have been fixed in version 1.9.2-1+deb7u2.

We recommend that you upgrade your simplesamlphp packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'simplesamlphp' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"simplesamlphp", ver:"1.9.2-1+deb7u2", rls:"DEB7"))) {
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
