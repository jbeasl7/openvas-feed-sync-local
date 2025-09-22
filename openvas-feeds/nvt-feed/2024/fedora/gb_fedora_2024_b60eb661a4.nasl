# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887392");
  script_cve_id("CVE-2024-42008", "CVE-2024-42009", "CVE-2024-42010");
  script_tag(name:"creation_date", value:"2024-08-16 04:04:34 +0000 (Fri, 16 Aug 2024)");
  script_version("2025-06-10T05:40:17+0000");
  script_tag(name:"last_modification", value:"2025-06-10 05:40:17 +0000 (Tue, 10 Jun 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-06 21:50:47 +0000 (Fri, 06 Sep 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-b60eb661a4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-b60eb661a4");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-b60eb661a4");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303070");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303075");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303095");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail' package(s) announced via the FEDORA-2024-b60eb661a4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Version 1.6.8**

- Managesieve: Protect special scripts in managesieve_kolab_master mode
- Fix newmail_notifier notification focus in Chrome (#9467)
- Fix fatal error when parsing some TNEF attachments (#9462)
- Fix double scrollbar when composing a mail with many plain text lines (#7760)
- Fix decoding mail parts with multiple base64-encoded text blocks (#9290)
- Fix bug where some messages could get malformed in an import from a MBOX file (#9510)
- Fix invalid line break characters in multi-line text in Sieve scripts (#9543)
- Fix bug where 'with attachment' filter could fail on some fts engines (#9514)
- Fix bug where an unhandled exception was caused by an invalid image attachment (#9475)
- Fix bug where a long subject title could not be displayed in some cases (#9416)
- Fix infinite loop when parsing malformed Sieve script (#9562)
- Fix bug where imap_conn_option's 'socket' was ignored (#9566)
- Fix XSS vulnerability in post-processing of sanitized HTML content **CVE-2024-42009**
- Fix XSS vulnerability in serving of attachments other than HTML or SVG **CVE-2024-42008**
- Fix information leak (access to remote content) via insufficient CSS filtering **CVE-2024-42010**");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.8~1.fc39", rls:"FC39"))) {
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
