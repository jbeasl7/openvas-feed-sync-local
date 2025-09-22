# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119058");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-11 13:20:01 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("libcurl Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_library_files_ssh_login_detect.nasl");
  script_mandatory_keys("linux_unix/library_file/ssh-login/detected");

  script_xref(name:"URL", value:"https://curl.se/libcurl/");

  script_tag(name:"summary", value:"SSH login-based detection of libcurl.");

  script_tag(name:"vuldetect", value:"Note: For a successful detection the 'string' tool needs to be
  installed on the target host.");

  # nb: Closest fitting tag for such .so files
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

if( ! soc = ssh_login_or_reuse_connection() )
  exit( 0 );

port = kb_ssh_transport();

if( ! full_path_list = get_kb_list( "linux_unix/library_file/ssh-login/" + port + "/files" ) ) {
  ssh_close_connection();
  exit( 0 );
}

# e.g. (all always from the same file grouped together)
#
# Debian 13 (libcurl4t64 8.14.1-2)
#
# libcurl/8.14.1
# CLIENT libcurl 8.14.1
# CLIENT libcurl 8.14.1
# CLIENT libcurl 8.14.1
#
# Debian 11.5 (libcurl4/libcurl3-gnutls with version 7.74.0-1.3+deb11u3)
#
# CLIENT libcurl 7.74.0
# CLIENT libcurl 7.74.0
# CLIENT libcurl 7.74.0
# 7.74.0
#
# Debian 10.10 (libcurl4/libcurl3-gnutls with version 7.64.0-4+deb10u2)
#
# CLIENT libcurl 7.64.0
# CLIENT libcurl 7.64.0
# CLIENT libcurl 7.64.0
# 7.64.0
#
# Debian 9.2 (libcurl3/libcurl3-gnutls with version 7.52.1-5+deb9u2)
#
# CLIENT libcurl 7.52.1
# CLIENT libcurl 7.52.1
# CLIENT libcurl 7.52.1
# 7.52.1
#
# Debian 8.9 (libcurl3/libcurl3-gnutls with version 7.38.0-4+deb8u7)
#
# CLIENT libcurl 7.38.0
# CLIENT libcurl 7.38.0
# CLIENT libcurl 7.38.0
# 7.38.0
#
# Ubuntu 22.04.5 (libcurl4/libcurl3-gnutls with version 7.81.0-1ubuntu1.20)
#
# CLIENT libcurl 7.81.0
# CLIENT libcurl 7.81.0
# CLIENT libcurl 7.81.0
# 7.81.0
#
# SLES 12 SP 5 (libcurl4-32bit-7.60.0-9.8.x86_64/libcurl4-7.60.0-9.8.x86_64)
#
# CLIENT libcurl 7.60.0
# CLIENT libcurl 7.60.0
# CLIENT libcurl 7.60.0
# 7.60.0
#
# EulerOS 2.0 SP9 (libcurl-7.69.1-2.eulerosv2r9.x86_64)
#
# CLIENT libcurl 7.69.1
# CLIENT libcurl 7.69.1
# CLIENT libcurl 7.69.1
# libcurl/7.69.1
# libcurl.so.4.6.0-7.69.1-2.eulerosv2r9.x86_64.debug
#
# CentOS 7 (libcurl-7.29.0-57.el7.x86_64)
#
# CLIENT libcurl 7.29.0
# CLIENT libcurl 7.29.0
# CLIENT libcurl 7.29.0
# 7.29.0
#
# Fedora 40 (libcurl-7.82.0-8.fc36.x86_64)
#
# CLIENT libcurl 7.82.0
# CLIENT libcurl 7.82.0
# CLIENT libcurl 7.82.0
# libcurl/7.82.0
# libcurl.so.4.7.0-7.82.0-8.fc36.x86_64.debug
#
# SLES 15 SP2 (libcurl4-7.66.0-4.6.1.x86_64)
#
# CLIENT libcurl 7.66.0
# CLIENT libcurl 7.66.0
# CLIENT libcurl 7.66.0
# libcurl.so.4.6.0-7.66.0-4.6.1.x86_64.debug
#
# openEuler 24.03 LTS (libcurl-8.4.0-3.oe2403.x86_64)
#
# libcurl/8.4.0
# CLIENT libcurl 8.4.0
# CLIENT libcurl 8.4.0
# CLIENT libcurl 8.4.0
# libcurl.so.4.8.0-8.4.0-3.oe2403.x86_64.debug
#
# nb:
# - As the "strings" command might contain different strings (especially with the return_errors:TRUE
#   used below) this was made a little bit more strict for now
# - The pattern with the "CLIENT" is preferred as it is always there it seems
# - The strings only including the version like e.g. "7.38.0" are not really of any use as we can't
#   grab them in a reliable way
# - The "libcurl.so." one seems to include the version after the first dash (the numbers before the
#   dash are the file name and usually not the real version...)
pattern = "^(CLIENT libcurl|libcurl/|libcurl\.so\.[0-9.]+-)\s*([0-9]+\.[0-9]+\.[0-9]+)";
found = FALSE;
report = ""; # nb: To make openvas-nasl-lint happy...

# nb: No need to do a "chomp()" here as this is already done by the dependency detection
foreach full_path( full_path_list ) {

  # e.g.:
  #
  # /path/to/libcurl.so
  # /path/to/libcurl.so.4
  # /path/to/libcurl.so.3
  # /path/to/libcurl.so.4.7.0
  # /usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.3
  # /usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4
  # /usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4.7.0
  #
  # nb: The `libcurl-gnutls` seems to be the "GnuTLS" flavor on at least Debian
  #
  if( ! full_path || full_path !~ "/libcurl(-gnutls)?\.so" )
    continue;

  # nb:
  # - We can't rely on the version in the file name as it is either not fully included or have a
  #   wrong version like e.g. "libcurl.so.4.7.0" which was actually "7.79.1" (confirmed via strings)
  #   so we definitely need strings here...
  # - At least the .so file of libcurl on CentOS contains the string "No such file or directory"
  #   which is getting filtered out by ssh_cmd() by default so we need to return the Linux errors
  #   here as well (via the two TRUE commands below). This shouldn't be a big problem as our
  #   detection pattern above should be strict enough.
  cmd = "strings " + full_path;
  res = ssh_cmd( socket:soc, cmd:cmd, return_errors:TRUE, return_linux_errors_only:TRUE );
  if( ! res = chomp( res ) )
    continue;

  if( ! match = egrep( string:res, pattern:pattern, icase:FALSE ) )
    continue;

  vers = eregmatch( string:match, pattern:pattern, icase:FALSE );
  if( ! vers[2] )
    continue;

  version = vers[2];
  found = TRUE;

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:haxx:libcurl:" );
  if( ! cpe )
    cpe = "cpe:/a:haxx:libcurl";

  register_product( cpe:cpe, location:full_path, port:0, service:"ssh-login" );

  if( report )
    report += '\n\n';

  report += build_detection_report( app:"libcurl",
                                    version:version,
                                    install:full_path,
                                    cpe:cpe,
                                    extra:"- Used command: " + cmd,
                                    concluded:chomp( match )
                                  );
}

# nb: We only need to set the generic KB keys once so this was placed outside of the loop above.
# Same for the reporting...
if( found ) {
  set_kb_item( name:"libcurl/detected", value:TRUE );
  set_kb_item( name:"libcurl/ssh-login/detected", value:TRUE );
  log_message( port:0, data:report );
}

ssh_close_connection();

exit( 0 );
