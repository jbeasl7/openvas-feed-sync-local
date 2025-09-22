# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900334");
  script_version("2021-08-19T11:39:34+0000");
  script_tag(name:"last_modification", value:"2021-08-19 11:39:34 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sun/Oracle OpenJDK Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Sun/Oracle OpenJDK.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

files = ssh_find_file(file_name:"/java$", useregex:TRUE, sock:sock);
foreach file(files) {

  file = chomp(file);

  if(!file)
    continue;

  # There are differences in the output of the version between OpenJDK versions, we need to differ between both here:
  #
  # java version "1.7.0_171"
  # OpenJDK Runtime Environment (IcedTea 2.6.13) (7u171-2.6.13-1~deb7u1)
  # OpenJDK 64-Bit Server VM (build 24.171-b02, mixed mode)
  #
  # vs.
  #
  # openjdk version "11.0.2" 2019-01-15
  # OpenJDK Runtime Environment (build 11.0.2+9-Debian-3)
  # OpenJDK 64-Bit Server VM (build 11.0.2+9-Debian-3, mixed mode, sharing)
  #
  # vs.
  #
  # openjdk version "1.8.0_131"
  # OpenJDK Runtime Environment (IcedTea 3.4.0) (suse-10.10.3-x86_64)
  # OpenJDK 64-Bit Server VM (build 25.131-b11, mixed mode)
  #
  # vs.
  #
  # openjdk version "11.0.10" 2021-01-19
  # OpenJDK Runtime Environment (build 11.0.10+9-Ubuntu-0ubuntu1.20.04)
  # OpenJDK 64-Bit Server VM (build 11.0.10+9-Ubuntu-0ubuntu1.20.04, mixed mode, sharing)
  #
  # vs.
  #
  # openjdk version "11" 2018-09-25
  # OpenJDK Runtime Environment 18.9 (build 11+28)
  # OpenJDK 64-Bit Server VM 18.9 (build 11+28, mixed mode)

  ver = ssh_get_bin_version(full_prog_name:file, version_argv:"-version", ver_pattern:'(openjdk|java) version "([0-9]+\\.[0-9]+\\.[0-9._]+)?-?([b0-9]+)?.+', sock:sock);
  if("OpenJDK" >< ver) {

    version = "unknown";

    jvVer   = ereg_replace(pattern:"_|-", string:ver, replace:".");

    javaVer = eregmatch(pattern:'"([0-9]+\\.[0-9]+\\.[0-9]+)(\\.([0-9]+))?"', string:jvVer);
    if(javaVer[1] && javaVer[3]) {
      jvVer = javaVer[1] + ":update_" + javaVer[3];
    } else if(javaVer[1]) {
      jvVer = javaVer[1];
    } else {
      jvVer = eregmatch(pattern:'"([0-9.]+)"', string:jvVer);
      jvVer = jvVer[1];
    }

    if(jvVer) {

      version = jvVer;

      if(version_is_less(version:jvVer, test_version:"1.4.2.38") ||
         version_in_range(version:jvVer, test_version:"1.5", test_version2:"1.5.0.33") ||
         version_in_range(version:jvVer, test_version:"1.6", test_version2:"1.6.0.18")) {
        app_name = "Sun OpenJDK";
        base_cpe = "cpe:/a:sun:openjdk:";
      } else {
        app_name = "Oracle OpenJDK";
        base_cpe = "cpe:/a:oracle:openjdk:";
      }
    } else {
      app_name = "Sun/Oracle OpenJDK";
      base_cpe = "cpe:/a:oracle:openjdk:";
    }

    set_kb_item(name:"openjdk/detected", value:TRUE);
    register_and_report_cpe(app:app_name, ver:version, concluded:ver[0], base:base_cpe, expr:"^([:a-z0-9._]+)", insloc:file, regPort:0, regService:"ssh-login");
  }
}

ssh_close_connection();
exit(0);
