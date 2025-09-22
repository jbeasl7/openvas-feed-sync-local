# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884867");
  script_tag(name:"creation_date", value:"2023-09-24 01:20:31 +0000 (Sun, 24 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-217194e950)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-217194e950");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-217194e950");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239447");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239448");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail' package(s) announced via the FEDORA-2023-217194e950 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Release 1.6.3**

- Fix bug where installto.sh/update.sh scripts were removing some essential options from the config file (#9051)
- Update jQuery-UI to version 1.13.2 (#9041)
- Fix regression that broke use_secure_urls feature (#9052)
- Fix potential PHP fatal error when opening a message with message/rfc822 part (#8953)
- Fix bug where a duplicate `<title>` tag in HTML email could cause some parts being cut off (#9029)
- Fix bug where a list of folders could have been sorted incorrectly (#9057)
- Fix regression where LDAP addressbook 'filter' option was ignored (#9061)
- Fix wrong order of a multi-folder search result when sorting by size (#9065)
- Fix so install/update scripts do not require PEAR (#9037)
- Fix regression where some mail parts could have been decoded incorrectly, or not at all (#9096)
- Fix handling of an error case in Cyrus IMAP BINARY FETCH, fallback to non-binary FETCH (#9097)
- Fix PHP8 deprecation warning in the reconnect plugin (#9083)
- Fix 'Show source' on mobile with x_frame_options = deny (#9084)
- Fix various PHP warnings (#9098)
- Fix deprecated use of ldap_connect() in password's ldap_simple driver (#9060)
- Fix cross-site scripting (XSS) vulnerability in handling of linkrefs in plain text messages");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.3~1.fc39", rls:"FC39"))) {
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
