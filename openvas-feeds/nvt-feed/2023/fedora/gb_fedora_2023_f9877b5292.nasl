# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884776");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:05 +0000 (Sat, 16 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-f9877b5292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-f9877b5292");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-f9877b5292");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-phpmailer6' package(s) announced via the FEDORA-2023-f9877b5292 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Minor security note

* The DSN support added in 6.8.0 reflects the DSN back to the user in an error message if it is invalid. If a DSN uses user-supplied input (a very bad idea), it opens a distant possibility of XSS if the host app does not escape output. In an abundance of caution, malformed DSNs are no longer reflected in error messages.

Changes

* Don't reflect malformed DSNs in error messages to avert any risk of XSS
* Improve Simplified Chinese, Sinhalese, and Norwegian translations
* Don't use setAccessible in PHP >= 8.1 in tests
* Avoid a deprecation notice in PHP 8.3
* Fix link in readme");

  script_tag(name:"affected", value:"'php-phpmailer6' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"php-phpmailer6", rpm:"php-phpmailer6~6.8.1~1.fc39", rls:"FC39"))) {
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
