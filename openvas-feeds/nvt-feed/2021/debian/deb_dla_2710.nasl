# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892710");
  script_cve_id("CVE-2017-4965", "CVE-2017-4966", "CVE-2017-4967", "CVE-2019-11281", "CVE-2019-11287", "CVE-2021-22116");
  script_tag(name:"creation_date", value:"2021-07-20 03:00:19 +0000 (Tue, 20 Jul 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-04 19:05:03 +0000 (Wed, 04 Dec 2019)");

  script_name("Debian: Security Advisory (DLA-2710-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2710-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2710-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/rabbitmq-server");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rabbitmq-server' package(s) announced via the DLA-2710-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in rabbitmq-server, a message-broker software.

CVE-2017-4965

Several forms in the RabbitMQ management UI are vulnerable to XSS attacks.

CVE-2017-4966

RabbitMQ management UI stores signed-in user credentials in a browser's local storage without expiration, making it possible to retrieve them using a chained attack

CVE-2017-4967

Several forms in the RabbitMQ management UI are vulnerable to XSS attacks.

CVE-2019-11281

The virtual host limits page, and the federation management UI, which do not properly sanitize user input. A remote authenticated malicious user with administrative access could craft a cross site scripting attack that would gain access to virtual hosts and policy management information

CVE-2019-11287

The 'X-Reason' HTTP Header can be leveraged to insert a malicious Erlang format string that will expand and consume the heap, resulting in the server crashing.

CVE-2021-22116

A malicious user can exploit the vulnerability by sending malicious AMQP messages to the target RabbitMQ instance.

For Debian 9 stretch, these problems have been fixed in version 3.6.6-1+deb9u1.

We recommend that you upgrade your rabbitmq-server packages.

For the detailed security status of rabbitmq-server please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'rabbitmq-server' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"rabbitmq-server", ver:"3.6.6-1+deb9u1", rls:"DEB9"))) {
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
