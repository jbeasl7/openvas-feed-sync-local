# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.20");
  script_cve_id("CVE-2012-3512", "CVE-2013-6048", "CVE-2013-6359");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DLA-20-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-20-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/DLA-20-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'munin' package(s) announced via the DLA-20-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[ Christoph Biedl ]

munin-node: more secure state file handling, introducing a new plugin state directory root, owned by uid 0. Then each plugin runs in its own UID plugin state directory, owned by that UID. (Closes: #684075), (Closes: #679897), closes CVE-2012-3512.

plugins: use runtime $ENV{MUNIN_PLUGSTATE}. So all properly written plugins will use /var/lib/munin-node/plugin-state/$uid/$some_file now please report plugins that are still using /var/lib/munin/plugin-state/ as those might pose a security risk!

Don't abort data collection for a node due to malicious node, fixing munin#1397, CVE-2013-6048.

Validate multigraph plugin name, CVE-2013-6359.

For Debian 6 Squeeze, these issues have been fixed in munin version 1.4.5-3+deb6u1");

  script_tag(name:"affected", value:"'munin' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"munin", ver:"1.4.5-3+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"munin-common", ver:"1.4.5-3+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"munin-java-plugins", ver:"1.4.5-3+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"munin-node", ver:"1.4.5-3+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"munin-plugins-extra", ver:"1.4.5-3+deb6u1", rls:"DEB6"))) {
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
