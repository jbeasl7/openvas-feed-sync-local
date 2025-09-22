# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114472");
  script_version("2024-04-10T05:05:22+0000");
  script_tag(name:"last_modification", value:"2024-04-10 05:05:22 +0000 (Wed, 10 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-02 09:20:09 +0000 (Tue, 02 Apr 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-01 17:23:05 +0000 (Mon, 01 Apr 2024)");
  script_cve_id("CVE-2024-3094");
  script_name("Tukaani Project XZ Utils Backdoor (Feb/Mar 2024)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Malware");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"The XZ Utils of the Tukaani Project have been backdoored by an
  unknown threat actor in February and March 2024.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is installed on the
  target host.");

  script_tag(name:"insight", value:"Malicious code was discovered in the upstream tarballs of xz,
  starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process
  extracts a prebuilt object file from a disguised test file existing in the source code, which is
  then used to modify specific functions in the liblzma code. This results in a modified liblzma
  library that can be used by any software linked against this library, intercepting and modifying
  the data interaction with this library.

  Please see the references for more (technical) details / analysis.");

  script_tag(name:"affected", value:"As of 04/2024 the following Linux distributions are know to
  have shipped packages including the backdoor from the 5.6.0 and 5.6.1 tarball releases for a short
  amount of time:

  - Debian testing/trixie and unstable/sid

  - Kali Linux (Only kali-rolling between March 26th to March 29th)

  - openSUSE Tumbleweed and openSUSE MicroOS (between March 07th to March 28th)

  - Fedora 40 beta, Fedora 41 pre-release and Fedora Rawhide (current development version)

  - Alpine Linux Edge (active development)

  Note: Arch Linux and Gentoo had also shipped the known backdoored package but are not assumed to
  be prone to the known attack vector.");

  script_tag(name:"solution", value:"Affected Linux distributions have rolled back the published
  packages to an older state. Please run an update via the used package manager.");

  script_xref(name:"URL", value:"https://tukaani.org/xz-backdoor/");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2024/msg00057.html");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1068024");
  script_xref(name:"URL", value:"https://news.opensuse.org/2024/03/29/xz-backdoor/");
  script_xref(name:"URL", value:"https://www.redhat.com/en/blog/urgent-security-alert-fedora-41-and-rawhide-users");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272210");
  script_xref(name:"URL", value:"https://www.kali.org/blog/about-the-xz-backdoor/");
  script_xref(name:"URL", value:"https://build.opensuse.org/request/show/1163302");
  script_xref(name:"URL", value:"https://security.alpinelinux.org/vuln/CVE-2024-3094");
  script_xref(name:"URL", value:"https://archlinux.org/news/the-xz-package-has-been-backdoored/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/03/29/4");
  script_xref(name:"URL", value:"https://gist.github.com/thesamesam/223949d5a074ebc3dce9ee78baad9e27");
  script_xref(name:"URL", value:"https://boehs.org/node/everything-i-know-about-the-xz-backdoor");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/2024/2024-223608-1032.pdf");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("list_array_func.inc");

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

# Gathered from the following URLs in 04/2024:
# - https://packages.qa.debian.org/x/xz-utils.html
# - https://pkg.kali.org/pkg/xz-utils

affected_debs = make_list(
  "5.6.1-1",
  "5.6.0-0.2",
  "5.6.0-0.1"
);

# Names and versions gathered from the following URLs in 04/2024:
# - https://news.opensuse.org/2024/03/29/xz-backdoor/
# - https://download.opensuse.org/tumbleweed/iso/Changes.20240307.txt
# - https://download.opensuse.org/tumbleweed/iso/Changes.20240320.txt
# - https://download.opensuse.org/tumbleweed/iso/Changes.20240328.txt
# - https://www.redhat.com/en/blog/urgent-security-alert-fedora-41-and-rawhide-users
# - https://www.rpmfind.net/linux/rpm2html/search.php?query=liblzma.so.5&submit=Search+...&system=opensuse&arch=
# - https://www.rpmfind.net/linux/rpm2html/search.php?query=liblzma.so.5&submit=Search+...&system=fedora&arch=
# - https://www.rpmfind.net/linux/rpm2html/search.php?query=xz-libs&submit=Search+...&system=fedora&arch=
# - https://web.archive.org/web/20240308102254/https://rpmfind.net/linux/rpm2html/search.php?query=liblzma.so.5
#
# from some cache results on Google:
# - xz-libs-5.6.1-1.fc41
#
# and from the following "live" system:
# - openSUSE Tumbleweed (Snapshot20240321)
#
# Note: Some of the Fedora variants have been assumed.

affected_rpms = make_list(
  "liblzma5-5.6.1-1.1",
  "liblzma5-5.6.1-1",
  "liblzma5-5.6.0-1.1",
  "liblzma5-5.6.0-1",
  "liblzma5-32bit-5.6.1-1.1",
  "liblzma5-32bit-5.6.1-1",
  "liblzma5-32bit-5.6.0-1.1",
  "liblzma5-32bit-5.6.0-1",
  "xz-5.6.1-1.1",
  "xz-5.6.1-1",
  "xz-5.6.0-1.1",
  "xz-5.6.0-1",
  "xz-5.6.0-1.fc40",
  "xz-5.6.0-2.fc40",
  "xz-5.6.1-1.fc40",
  "xz-5.6.1-2.fc40",
  "xz-5.6.0-1.fc41",
  "xz-5.6.0-2.fc41",
  "xz-5.6.1-1.fc41",
  "xz-5.6.1-2.fc41",
  "xz-libs-5.6.0-1.fc40",
  "xz-libs-5.6.0-2.fc40",
  "xz-libs-5.6.1-1.fc40",
  "xz-libs-5.6.1-2.fc40",
  "xz-libs-5.6.0-1.fc41",
  "xz-libs-5.6.0-2.fc41",
  "xz-libs-5.6.1-1.fc41",
  "xz-libs-5.6.1-2.fc41"
);

# Affected versions gathered from the following commits on https://git.alpinelinux.org/aports/log/main/xz/APKBUILD:
# - First introduction of "5.6.1-r0" (previous version was "5.4.6-r0") with a revert in between:
#   - https://git.alpinelinux.org/aports/commit/main/xz/APKBUILD?id=11bc4fbf6b6fe935f77e45706b1b8a2923b2b203
#   - https://git.alpinelinux.org/aports/commit/main/xz/APKBUILD?id=a71682312f91902bcfde719761e3b00f492689f4
#   - https://git.alpinelinux.org/aports/commit/main/xz/APKBUILD?id=b612e91b402b16e6a4f28923e508eee59c1ce0aa
# - Bump to "5.6.1-r1": https://git.alpinelinux.org/aports/commit/main/xz/APKBUILD?id=f1434b8411f8209fd2e4c7f23b3ac1e1a6717bc6
#
# 5.6.1-r2 was the first not affected version:
# https://git.alpinelinux.org/aports/commit/main/xz/APKBUILD?id=982d2c6bcbbb579e85bb27c40be84072ca0b1fd9
#

affected_apks = make_list(
  "5.6.1-r0",
  "5.6.1-r1"
);

cmd = "dpkg -l xz-utils liblzma-dev liblzma5";
dpkg_res_full = ssh_cmd( socket:sock, cmd:cmd );
if( dpkg_res_full ) {

  report = 'The following known affected packages have been identified via a "' + cmd + '" query:\n';

  dpkg_res_split = split( dpkg_res_full, keep:FALSE );
  foreach dpkg_res_line( dpkg_res_split ) {

    # Affected (Debian testing/trixie):
    # ii  liblzma5:amd64 5.6.0-0.2    amd64        XZ-format compression library
    # ii  xz-utils       5.6.0-0.2    amd64        XZ-format compression utilities
    #
    # Not affected (Debian 12):
    # ii  liblzma5:amd64 5.4.1-0.2    amd64        XZ-format compression library
    # ii  xz-utils       5.4.1-0.2    amd64        XZ-format compression utilities
    #
    # Not affected (Debian testing/trixie with reverted packages):
    # ii  liblzma5:amd64 5.6.1+really5.4.5-1 amd64        XZ-format compression library
    # ii  xz-utils       5.6.1+really5.4.5-1 amd64        XZ-format compression utilities
    #
    # nb: Only packages in installed (ii) state are checked (at least currently)

    deb_pkg_vers = eregmatch( string:dpkg_res_line, pattern:'ii\\s+(xz-utils|liblzma-dev|liblzma5)(:[^ ]+)?\\s+([^ ]+)\\s+[^\r\n]+', icase:FALSE );
    if( deb_pkg_vers[3] ) {
      if( in_array( search:deb_pkg_vers[3], array:affected_debs, part_match:FALSE, icase:FALSE ) ) {
        report += '\n' + deb_pkg_vers[0];
        VULN = TRUE;
      }
    }
  }

  if( VULN ) {
    close( sock );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

cmd = "rpm -q liblzma5 liblzma5-32bit xz xz-libs --qf '%{NAME}-%{VERSION}-%{RELEASE}\n'";
rpm_res_full = ssh_cmd( socket:sock, cmd:cmd );

if( rpm_res_full ) {

  report = 'The following known affected packages have been identified via a "' + cmd + '" query:\n';

  rpm_res_split = split( rpm_res_full, keep:FALSE );
  foreach rpm_res_line( rpm_res_split ) {

    # Affected (openSUSE Tumbleweed (Snapshot20240321)):
    # liblzma5-5.6.1-1.1
    # xz-5.6.1-1.1
    #
    # Not affected (openSUSE Tumbleweed (Snapshot20240328)):
    # liblzma5-5.6.1.revertto5.4-2.1
    # xz-5.6.1.revertto5.4-2.1
    #
    # Affected (mentioned on the linked Red Hat Blog post above):
    # xz-libs-5.6.0-1.fc40
    # xz-libs-5.6.0-2.fc40
    #
    # Not affected (fedora:40, fedora:41 and fedora:rawhide tags from https://hub.docker.com/_/fedora as of 04/2024):
    # xz-libs-5.4.6-1.fc40
    #
    # Not affected (Fedora 39)
    # xz-5.4.1-1.fc38
    # xz-libs-5.4.1-1.fc38
    #
    # Not affected (Fedora 40 beta after yum update)
    # xz-5.4.6-3.fc40
    # xz-libs-5.4.6-3.fc40

    if( in_array( search:rpm_res_line, array:affected_rpms, part_match:FALSE, icase:FALSE ) ) {
      report += '\n' + rpm_res_line;
      VULN = TRUE;
    }
  }

  if( VULN ) {
    close( sock );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

# Some background info on Alpine Linux apk commands is available here:
# https://www.cyberciti.biz/faq/alpine-linux-apk-list-files-in-package/
cmd = "apk list --installed | egrep '^xz(-libs)?-[0-9.]+'";

# nb: "return_linux_errors_only:TRUE" is used here because the command might return something like
# e.g. the following below and int that case our ssh_cmd() would have returned NULL:
#
# WARNING: opening from cache https://dl-cdn.alpinelinux.org/alpine/edge/main: No such file or directory
# WARNING: opening from cache https://dl-cdn.alpinelinux.org/alpine/edge/community: No such file or directory
# xz-5.6.1-r2 x86_64 {xz} (GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later) [installed]
apk_res_full = ssh_cmd( socket:sock, cmd:cmd, return_errors:TRUE, return_linux_errors_only:TRUE );
close( sock );

if( apk_res_full ) {

  report = 'The following known affected packages have been identified via a "' + cmd + '" query:\n';

  apk_res_split = split( apk_res_full, keep:FALSE );
  foreach apk_res_line( apk_res_split ) {

    # Affected e.g.:
    # xz-5.6.1-r1 x86_64 {xz} (GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later) [installed]
    # xz-libs-5.6.1-r1 x86_64 {xz} (GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later) [installed]
    #
    # Not affected e.g.:
    # xz-5.6.1-r2 x86_64 {xz} (GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later) [installed]
    # xz-libs-5.6.1-r2 x86_64 {xz} (GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later) [installed]
    #

    apk_vers = eregmatch( string:apk_res_line, pattern:"xz(-libs)?-([^ ]+)", icase:FALSE );
    if( apk_vers[2] ) {
      if( in_array( search:apk_vers[2], array:affected_apks, part_match:FALSE, icase:FALSE ) ) {
        report += '\n' + apk_vers[0];
        VULN = TRUE;
      }
    }
  }

  if( VULN ) {
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 0 ); # nb: No exit(99); as the package might have been installed via other means or we're scanning an unknown system...
