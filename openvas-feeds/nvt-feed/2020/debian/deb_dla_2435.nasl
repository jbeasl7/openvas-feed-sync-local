# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892435");
  script_cve_id("CVE-2020-9497", "CVE-2020-9498");
  script_tag(name:"creation_date", value:"2020-11-07 04:00:10 +0000 (Sat, 07 Nov 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-21 16:02:32 +0000 (Tue, 21 Jul 2020)");

  script_name("Debian: Security Advisory (DLA-2435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2435-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/DLA-2435-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/guacamole-server");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'guacamole-server' package(s) announced via the DLA-2435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The server component of Apache Guacamole, a remote desktop gateway, did not properly validate data received from RDP servers. This could result in information disclosure or even the execution of arbitrary code.

CVE-2020-9497

Apache Guacamole does not properly validate data received from RDP servers via static virtual channels. If a user connects to a malicious or compromised RDP server, specially-crafted PDUs could result in disclosure of information within the memory of the guacd process handling the connection.

CVE-2020-9498

Apache Guacamole may mishandle pointers involved in processing data received via RDP static virtual channels. If a user connects to a malicious or compromised RDP server, a series of specially-crafted PDUs could result in memory corruption, possibly allowing arbitrary code to be executed with the privileges of the running guacd process.

For Debian 9 stretch, these problems have been fixed in version 0.9.9-2+deb9u1.

We recommend that you upgrade your guacamole-server packages.

For the detailed security status of guacamole-server please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'guacamole-server' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"guacd", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libguac-client-rdp0", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libguac-client-ssh0", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libguac-client-telnet0", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libguac-client-vnc0", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libguac-dev", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libguac11", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
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
