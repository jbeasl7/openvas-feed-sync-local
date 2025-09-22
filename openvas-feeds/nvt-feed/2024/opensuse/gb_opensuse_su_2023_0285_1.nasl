# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833073");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:39:33 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for roundcubemail (openSUSE-SU-2023:0285-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0285-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FES4IKTZTYNBS3TCVPNOFHD7POSFJHYY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail'
  package(s) announced via the openSUSE-SU-2023:0285-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for roundcubemail fixes the following issues:

     Update to 1.6.3 (boo#1215433)

  * Fix bug where installto.sh/update.sh scripts were removing some
       essential options from the config file (#9051)

  * Update jQuery-UI to version 1.13.2 (#9041)

  * Fix regression that broke use_secure_urls feature (#9052)

  * Fix potential PHP fatal error when opening a message with message/rfc822
       part (#8953)

  * Fix bug where a duplicate  title  tag in HTML email could cause some
       parts being cut off (#9029)

  * Fix bug where a list of folders could have been sorted incorrectly
       (#9057)

  * Fix regression where LDAP addressbook 'filter' option was ignored (#9061)

  * Fix wrong order of a multi-folder search result when sorting by size
       (#9065)

  * Fix so install/update scripts do not require PEAR (#9037)

  * Fix regression where some mail parts could have been decoded
       incorrectly, or not at all (#9096)

  * Fix handling of an error case in Cyrus IMAP BINARY FETCH, fallback to
       non-binary FETCH (#9097)

  * Fix PHP8 deprecation warning in the reconnect plugin (#9083)

  * Fix 'Show source' on mobile with x_frame_options = deny (#9084)

  * Fix various PHP warnings (#9098)

  * Fix deprecated use of ldap_connect() in password's ldap_simple driver
       (#9060)

  * Fix cross-site scripting (XSS) vulnerability in handling of linkrefs in
       plain text messages

     Update to 1.6.2

  * Add Uyghur localization

  * Fix regression in OAuth request URI caused by use of REQUEST_URI instead
       of SCRIPT_NAME as a default (#8878)

  * Fix bug where false attachment reminder was displayed on HTML mail with
       inline images (#8885)

  * Fix bug where a non-ASCII character in app.js could cause error in
       javascript engine (#8894)

  * Fix JWT decoding with url safe base64 schema (#8890)

  * Fix bug where .wav instead of .mp3 file was used for the new mail
       notification in Firefox (#8895)

  * Fix PHP8 warning (#8891)

  * Fix support for Windows-31J charset (#8869)

  * Fix so LDAP VLV option is disabled by default as documented (#8833)

  * Fix so an email address with name is supported as input to the
       managesieve notify :from parameter (#8918)

  * Fix Help plugin menu (#8898)

  * Fix invalid onclick handler on the logo image when using non-array
       skin_logo setting (#8933)

  * Fix duplicate recipients in 'To' and 'Cc' on reply (#8912)

  * Fix bug where it wasn't possible to scroll lists by clicking middle
       mouse butto ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.3~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.3~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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
