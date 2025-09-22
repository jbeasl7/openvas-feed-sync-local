# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893077");
  script_cve_id("CVE-2022-31163");
  script_tag(name:"creation_date", value:"2022-08-19 01:00:24 +0000 (Fri, 19 Aug 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-03 18:31:43 +0000 (Wed, 03 Aug 2022)");

  script_name("Debian: Security Advisory (DLA-3077-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3077-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3077-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-tzinfo' package(s) announced via the DLA-3077-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential directory traversal vulnerablilty in ruby-tzinfo, a timezone library for the Ruby programming language.

CVE-2022-31163

TZInfo is a Ruby library that provides access to time zone data and allows times to be converted using time zone rules. Versions prior to 0.36.1, as well as those prior to 1.2.10 when used with the Ruby data source tzinfo-data, are vulnerable to relative path traversal. With the Ruby data source, time zones are defined in Ruby files. There is one file per time zone. Time zone files are loaded with `require` on demand. In the affected versions, `TZInfo::Timezone.get` fails to validate time zone identifiers correctly, allowing a new line character within the identifier. With Ruby version 1.9.3 and later, `TZInfo::Timezone.get` can be made to load unintended files with `require`, executing them within the Ruby process. Versions 0.3.61 and 1.2.10 include fixes to correctly validate time zone identifiers. Versions 2.0.0 and later are not vulnerable. Version 0.3.61 can still load arbitrary files from the Ruby load path if their name follows the rules for a valid time zone identifier and the file has a prefix of `tzinfo/definition` within a directory in the load path. Applications should ensure that untrusted files are not placed in a directory on the load path. As a workaround, the time zone identifier can be validated before passing to `TZInfo::Timezone.get` by ensuring it matches the regular expression `A[A-Za-z0-9+-_]+(?:/[A-Za-z0-9+-_]+)*z`.

For Debian 10 Buster, these problems have been fixed in version 1.2.5-1+deb10u1.

We recommend that you upgrade your ruby-tzinfo packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-tzinfo' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-tzinfo", ver:"1.2.5-1+deb10u1", rls:"DEB10"))) {
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
