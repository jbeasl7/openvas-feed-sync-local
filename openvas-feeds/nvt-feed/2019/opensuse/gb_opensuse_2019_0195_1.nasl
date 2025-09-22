# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852298");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-16843", "CVE-2018-16844", "CVE-2018-16845");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 17:50:00 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2019-02-19 04:05:58 +0100 (Tue, 19 Feb 2019)");
  script_name("openSUSE: Security Advisory for nginx (openSUSE-SU-2019:0195-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"openSUSE-SU", value:"2019:0195-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00036.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx'
  package(s) announced via the openSUSE-SU-2019:0195-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nginx fixes the following issues:

  nginx was updated to 1.14.2:

  - Bugfix: nginx could not be built on Fedora 28 Linux.

  - Bugfix: in handling of client addresses when using unix domain listen
  sockets to work with datagrams on Linux.

  - Change: the logging level of the 'http request', 'https proxy request',
  'unsupported protocol', 'version too low', 'no suitable key share', and
  'no suitable signature algorithm' SSL errors has been lowered from
  'crit' to 'info'.

  - Bugfix: when using OpenSSL 1.1.0 or newer it was not possible to switch
  off 'ssl_prefer_server_ciphers' in a virtual server if it was switched
  on in the default server.

  - Bugfix: nginx could not be built with LibreSSL 2.8.0.

  - Bugfix: if nginx was built with OpenSSL 1.1.0 and used with OpenSSL
  1.1.1, the TLS 1.3 protocol was always enabled.

  - Bugfix: sending a disk-buffered request body to a gRPC backend might
  fail.

  - Bugfix: connections with some gRPC backends might not be cached when
  using the 'keepalive' directive.

  - Bugfix: a segmentation fault might occur in a worker process if the
  ngx_http_mp4_module was used on 32-bit platforms.

  Changes with nginx 1.14.1:

  - Security: when using HTTP/2 a client might cause excessive memory
  consumption (CVE-2018-16843) and CPU usage (CVE-2018-16844).

  - Security: processing of a specially crafted mp4 file with the
  ngx_http_mp4_module might result in worker process memory disclosure
  (CVE-2018-16845).

  - Bugfix: working with gRPC backends might result in excessive memory
  consumption.

  Changes with nginx 1.13.12:

  - Bugfix: connections with gRPC backends might be closed unexpectedly when
  returning a large response.

  Changes with nginx 1.13.10

  - Feature: the 'set' parameter of the 'include' SSI directive now allows
  writing arbitrary responses to a variable  the
  'subrequest_output_buffer_size' directive defines maximum response size.

  - Feature: now nginx uses clock_gettime(CLOCK_MONOTONIC) if available, to
  avoid timeouts being incorrectly triggered on system time changes.

  - Feature: the 'escape=none' parameter of the 'log_format' directive.
  Thanks to Johannes Baiter and Calin Don.

  - Feature: the $ssl_preread_alpn_protocols variable in the
  ngx_stream_ssl_preread_module.

  - Feature: the ngx_http_grpc_module.

  - Bugfix: in memory allocation error handling in the 'geo' directive.

  - Bugfix: when using variables in the 'auth_basic_user_file' directive a
  null character might appear in logs. Thanks to Vadim Filimonov.

  Patch Instructions:

  To install this openSUSE Security Up ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"nginx on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"nginx", rpm:"nginx~1.14.2~2.7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debuginfo", rpm:"nginx-debuginfo~1.14.2~2.7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debugsource", rpm:"nginx-debugsource~1.14.2~2.7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-plugin-nginx", rpm:"vim-plugin-nginx~1.14.2~2.7.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.0") {
  if(!isnull(res = isrpmvuln(pkg:"nginx", rpm:"nginx~1.14.2~lp150.2.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debuginfo", rpm:"nginx-debuginfo~1.14.2~lp150.2.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debugsource", rpm:"nginx-debugsource~1.14.2~lp150.2.4.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-plugin-nginx", rpm:"vim-plugin-nginx~1.14.2~lp150.2.4.1", rls:"openSUSELeap15.0"))) {
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
