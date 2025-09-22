# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891716");
  script_cve_id("CVE-2019-9187");
  script_tag(name:"creation_date", value:"2019-03-18 23:00:00 +0000 (Mon, 18 Mar 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-06 18:40:29 +0000 (Thu, 06 Jun 2019)");

  script_name("Debian: Security Advisory (DLA-1716-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1716-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1716-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ikiwiki' package(s) announced via the DLA-1716-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ikiwiki maintainers discovered that the aggregate plugin did not use LWPx::ParanoidAgent. On sites where the aggregate plugin is enabled, authorized wiki editors could tell ikiwiki to fetch potentially undesired URIs even if LWPx::ParanoidAgent was installed:

local files via file: URIs other URI schemes that might be misused by attackers, such as gopher: hosts that resolve to loopback IP addresses (127.x.x.x) hosts that resolve to RFC 1918 IP addresses (192.168.x.x etc.)

This could be used by an attacker to publish information that should not have been accessible, cause denial of service by requesting tarpit URIs that are slow to respond, or cause undesired side-effects if local web servers implement unsafe GET requests. (CVE-2019-9187)

Additionally, if liblwpx-paranoidagent-perl is not installed, the blogspam, openid and pinger plugins would fall back to LWP, which is susceptible to similar attacks. This is unlikely to be a practical problem for the blogspam plugin because the URL it requests is under the control of the wiki administrator, but the openid plugin can request URLs controlled by unauthenticated remote users, and the pinger plugin can request URLs controlled by authorized wiki editors.

This is addressed in ikiwiki 3.20190228 as follows, with the same fixes backported to Debian 9 in version 3.20170111.1:

URI schemes other than http: and https: are not accepted, preventing access to file:, gopher:, etc.

If a proxy is configured in the ikiwiki setup file, it is used for all outgoing http: and https: requests. In this case the proxy is responsible for blocking any requests that are undesired, including loopback or RFC 1918 addresses.

If a proxy is not configured, and liblwpx-paranoidagent-perl is installed, it will be used. This prevents loopback and RFC 1918 IP addresses, and sets a timeout to avoid denial of service via tarpit URIs.

Otherwise, the ordinary LWP user-agent will be used. This allows requests to loopback and RFC 1918 IP addresses, and has less robust timeout behaviour. We are not treating this as a vulnerability: if this behaviour is not acceptable for your site, please make sure to install LWPx::ParanoidAgent or disable the affected plugins.

For Debian 8 Jessie, this problem has been fixed in version 3.20141016.4+deb8u1.

We recommend that you upgrade your ikiwiki packages. In addition it is also recommended that you have liblwpx-paranoidagent-perl installed, which listed in the recommends field of ikiwiki.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ikiwiki' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"ikiwiki", ver:"3.20141016.4+deb8u1", rls:"DEB8"))) {
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
