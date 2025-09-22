# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119052");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-07 13:14:16 +0000 (Mon, 07 Jul 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OpenSSL Library (.so) Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_library_files_ssh_login_detect.nasl");
  script_mandatory_keys("linux_unix/library_file/ssh-login/detected");

  script_tag(name:"summary", value:"SSH login-based detection of OpenSSL.");

  script_tag(name:"vuldetect", value:"Notes:

  - For a successful detection the 'string' tool needs to be installed on the target host

  - This routine detects OpenSSL based on the availability of the 'libcrypto.so' and/or 'libssl.so'
  library files");

  # nb: Closest fitting tag for such .so files
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");

if( ! soc = ssh_login_or_reuse_connection() )
  exit( 0 );

port = kb_ssh_transport();

if( ! full_path_list = get_kb_list( "linux_unix/library_file/ssh-login/" + port + "/files" ) ) {
  ssh_close_connection();
  exit( 0 );
}

# OpenSSL 1.0.2l  25 May 2017
# OpenSSL 1.1.1d  10 Sep 2019
# OpenSSL 1.0.1i 6 Aug 2014
# OpenSSL 1.1.1f  31 Mar 2020
# OpenSSL 3.0.5 5 Jul 2022
# OpenSSL 3.5.0 8 Apr 2025
#
# On at least Fedora 40 the above strings haven't been included and only these ones:
#
# {"type":"rpm","name":"openssl","version":"3.0.5-1.fc36","architecture":"x86_64","osCpe":"cpe:/o:fedoraproject:fedora:36"}
# libssl.so.3.0.5-3.0.5-1.fc36.x86_64.debug
#
# These ones are from openEuler 24.04 LTS:
#
# - /usr/lib64/libssl.so.1.1:
# OpenSSL 1.1.1m  14 Dec 2021
# libssl.so.1.1.1m-1.1.1m-10.oe2403.x86_64.debug
# - /usr/lib64/libssl.so.3 (only this single one):
# libssl.so.3.0.12-3.0.12-5.oe2403.x86_64.debug
#
# nb:
# - As the "strings" command might contain different strings (especially with the return_errors:TRUE
#   used below) this was made a little bit more strict for now
# - ".*" is used in the second part of the regex as we don't want to add a pattern for the full
#   string above as the order might differ
# - The "libssl.so." one seems to include the version after the first dash (the numbers before the
#   dash are the file name and usually not the real version...)
pattern = '^(OpenSSL\\s*|.*"name"\\s*:\\s*"openssl"\\s*,\\s*"version"\\s*:\\s*"|lib(crypto|ssl)\\.so\\.[0-9.]+-)([0-9]+\\.[0-9]+\\.[0-9.a-z]+)';
found = FALSE;

# nb: No need to do a "chomp()" here as this is already done by the dependency detection
foreach full_path( full_path_list ) {

  # e.g.:
  #
  # /<redacted>/.rvm/src/openssl-1.0.1i/libcrypto.so
  # /<redacted>/.rvm/src/openssl-1.0.1i/libcrypto.so.1.0.0
  # /<redacted>/.rvm/src/openssl-1.0.1i/libssl.so
  # /<redacted>/.rvm/src/openssl-1.0.1i/libssl.so.1.0.0
  # /<redacted>/.rvm/usr/lib/libcrypto.so
  # /<redacted>/.rvm/usr/lib/libcrypto.so.1.0.0
  # /<redacted>/.rvm/usr/lib/libssl.so
  # /<redacted>/.rvm/usr/lib/libssl.so.1.0.0
  # /opt/yubico-authenticator/helper/_internal/libcrypto.so.1.1
  # /opt/yubico-authenticator/helper/_internal/libssl.so.1.1
  # /usr/lib/x86_64-linux-gnu/libcrypto.so
  # /usr/lib/x86_64-linux-gnu/libcrypto.so.3
  # /usr/lib/x86_64-linux-gnu/libssl.so
  # /usr/lib/x86_64-linux-gnu/libssl.so.3
  # /usr/lib64/libssl.so.1.1.1f
  # /usr/lib64/libssl.so.1.1
  # /usr/lib64/libcrypto.so.1.1.1f
  # /usr/lib64/libcrypto.so.1.1
  #
  if( ! full_path || full_path !~ "/lib(crypto|ssl)\.so" )
    continue;

  # nb:
  # - We can't rely on the version in the file name as it is either not fully included or have a
  #   wrong version like e.g. "/lib64/libssl.so.1.0.0" which was actually "1.0.2p" (confirmed via
  #   strings) so we definitely need strings here...
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
  if( ! vers[3] )
    continue;

  found = TRUE;
  set_kb_item( name:"openssl/ssh-login/" + port + "/installs", value:"0#---#" + full_path + "#---#" + vers[3] + "#---#" + chomp( match ) + "#---#- Used command: " + cmd );
}

# nb: We only need to set the generic KB keys once so this was placed outside of the loop above.
if( found ) {
  set_kb_item( name:"openssl/detected", value:TRUE );
  set_kb_item( name:"openssl_or_gnutls/detected", value:TRUE );
  set_kb_item( name:"openssl/ssh-login/detected", value:TRUE );
}

ssh_close_connection();

exit( 0 );
