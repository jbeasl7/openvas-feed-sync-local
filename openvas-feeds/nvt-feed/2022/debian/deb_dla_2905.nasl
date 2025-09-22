# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892905");
  script_cve_id("CVE-2021-4104", "CVE-2022-23302", "CVE-2022-23305", "CVE-2022-23307");
  script_tag(name:"creation_date", value:"2022-02-01 02:00:08 +0000 (Tue, 01 Feb 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-14 16:42:01 +0000 (Thu, 14 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-2905-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2905-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2905-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/apache-log4j1.2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache-log4j1.2' package(s) announced via the DLA-2905-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in Apache Log4j 1.2, a Java logging framework, when it is configured to use JMSSink, JDBCAppender, JMSAppender or Apache Chainsaw which could be exploited for remote code execution.

Note that a possible attacker requires write access to the Log4j configuration and the aforementioned features are not enabled by default. In order to completely mitigate against these type of vulnerabilities the related classes have been removed from the resulting jar file.

For Debian 9 stretch, these problems have been fixed in version 1.2.17-7+deb9u2.

We recommend that you upgrade your apache-log4j1.2 packages.

For the detailed security status of apache-log4j1.2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'apache-log4j1.2' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liblog4j1.2-java", ver:"1.2.17-7+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblog4j1.2-java-doc", ver:"1.2.17-7+deb9u2", rls:"DEB9"))) {
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
