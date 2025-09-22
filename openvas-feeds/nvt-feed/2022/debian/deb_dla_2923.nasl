# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892923");
  script_cve_id("CVE-2021-42392", "CVE-2022-23221");
  script_tag(name:"creation_date", value:"2022-02-16 02:00:14 +0000 (Wed, 16 Feb 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-26 02:44:30 +0000 (Wed, 26 Jan 2022)");

  script_name("Debian: Security Advisory (DLA-2923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2923-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2923-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/h2database");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'h2database' package(s) announced via the DLA-2923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security researchers of JFrog Security and Ismail Aydemir discovered two remote code execution vulnerabilities in the H2 Java SQL database engine which can be exploited through various attack vectors, most notably through the H2 Console and by loading custom classes from remote servers through JNDI. The H2 console is a developer tool and not required by any reversedependency in Debian. It has been disabled in (old)stable releases. Database developers are advised to use at least version 2.1.210-1, currently available in Debian unstable.

For Debian 9 stretch, these problems have been fixed in version 1.4.193-1+deb9u1.

We recommend that you upgrade your h2database packages.

For the detailed security status of h2database please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'h2database' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libh2-java", ver:"1.4.193-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libh2-java-doc", ver:"1.4.193-1+deb9u1", rls:"DEB9"))) {
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
