# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702929");
  script_cve_id("CVE-2014-0081", "CVE-2014-0082", "CVE-2014-0130");
  script_tag(name:"creation_date", value:"2014-05-15 22:00:00 +0000 (Thu, 15 May 2014)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:57:52 +0000 (Tue, 16 Jul 2024)");

  script_name("Debian: Security Advisory (DSA-2929-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2929-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2929-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2929");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-actionpack-3.2' package(s) announced via the DSA-2929-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Action Pack, a component of Ruby on Rails.

CVE-2014-0081

actionview/lib/action_view/helpers/number_helper.rb contains multiple cross-site scripting vulnerabilities

CVE-2014-0082

actionpack/lib/action_view/template/text.rb performs symbol interning on MIME type strings, allowing remote denial-of-service attacks via increased memory consumption.

CVE-2014-0130

A directory traversal vulnerability in actionpack/lib/abstract_controller/base.rb allows remote attackers to read arbitrary files.

For the stable distribution (wheezy), these problems have been fixed in version 3.2.6-6+deb7u2.

We recommend that you upgrade your ruby-actionpack-3.2 packages.");

  script_tag(name:"affected", value:"'ruby-actionpack-3.2' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-actionpack-3.2", ver:"3.2.6-6+deb7u2", rls:"DEB7"))) {
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
