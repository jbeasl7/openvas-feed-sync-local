# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892583");
  script_cve_id("CVE-2017-15709", "CVE-2018-11775", "CVE-2019-0222", "CVE-2021-26117");
  script_tag(name:"creation_date", value:"2021-03-06 04:00:10 +0000 (Sat, 06 Mar 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-04 15:54:38 +0000 (Thu, 04 Feb 2021)");

  script_name("Debian: Security Advisory (DLA-2583-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2583-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2583-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/activemq");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'activemq' package(s) announced via the DLA-2583-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in activemq, a message broker built around Java Message Service.

CVE-2017-15709

When using the OpenWire protocol in activemq, it was found that certain system details (such as the OS and kernel version) are exposed as plain text.

CVE-2018-11775

TLS hostname verification when using the Apache ActiveMQ Client was missing which could make the client vulnerable to a MITM attack between a Java application using the ActiveMQ client and the ActiveMQ server. This is now enabled by default.

CVE-2019-0222

Unmarshalling corrupt MQTT frame can lead to broker Out of Memory exception making it unresponsive

CVE-2021-26117

The optional ActiveMQ LDAP login module can be configured to use anonymous access to the LDAP server. The anonymous context is used to verify a valid users password in error, resulting in no check on the password.

For Debian 9 stretch, these problems have been fixed in version 5.14.3-3+deb9u2.

We recommend that you upgrade your activemq packages.

For the detailed security status of activemq please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'activemq' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"activemq", ver:"5.14.3-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactivemq-java", ver:"5.14.3-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactivemq-java-doc", ver:"5.14.3-3+deb9u2", rls:"DEB9"))) {
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
