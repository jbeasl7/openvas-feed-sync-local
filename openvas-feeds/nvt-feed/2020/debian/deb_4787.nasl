# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704787");
  script_cve_id("CVE-2020-15275", "CVE-2020-25074");
  script_tag(name:"creation_date", value:"2020-11-10 06:30:12 +0000 (Tue, 10 Nov 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-24 17:20:03 +0000 (Tue, 24 Nov 2020)");

  script_name("Debian: Security Advisory (DSA-4787-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4787-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4787-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4787");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/moin");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moin' package(s) announced via the DSA-4787-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in moin, a Python clone of WikiWiki.

CVE-2020-15275

Catarina Leite discovered that moin is prone to a stored XSS vulnerability via SVG attachments.

CVE-2020-25074

Michael Chapman discovered that moin is prone to a remote code execution vulnerability via the cache action.

For the stable distribution (buster), these problems have been fixed in version 1.9.9-1+deb10u1.

We recommend that you upgrade your moin packages.

For the detailed security status of moin please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'moin' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"python-moinmoin", ver:"1.9.9-1+deb10u1", rls:"DEB10"))) {
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
