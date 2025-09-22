# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893260");
  script_cve_id("CVE-2021-21366", "CVE-2022-39353");
  script_tag(name:"creation_date", value:"2023-01-02 02:00:10 +0000 (Mon, 02 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-04 12:29:27 +0000 (Fri, 04 Nov 2022)");

  script_name("Debian: Security Advisory (DLA-3260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3260-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3260-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/node-xmldom");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-xmldom' package(s) announced via the DLA-3260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that node-xmldom, a standard XML DOM (Level2 CORE) implementation in pure javascript, processed ill-formed XML, which may result in bugs and security holes in downstream applications.

CVE-2021-21366

xmldom versions 0.4.0 and older do not correctly preserve system identifiers, FPIs or namespaces when repeatedly parsing and serializing maliciously crafted documents. This may lead to unexpected syntactic changes during XML processing in some downstream applications.

CVE-2022-39353

Mark Gollnick discovered that xmldom parses XML that is not well-formed because it contains multiple top level elements, and adds all root nodes to the childNodes collection of the Document, without reporting or throwing any error. This breaks the assumption that there is only a single root node in the tree, and may open security holes such as CVE-2022-39299 in downstream applications.

For Debian 10 buster, these problems have been fixed in version 0.1.27+ds-1+deb10u2.

We recommend that you upgrade your node-xmldom packages.

For the detailed security status of node-xmldom please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'node-xmldom' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"node-xmldom", ver:"0.1.27+ds-1+deb10u2", rls:"DEB10"))) {
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
