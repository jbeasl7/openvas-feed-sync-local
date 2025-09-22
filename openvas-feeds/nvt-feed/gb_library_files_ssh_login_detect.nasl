# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119051");
  script_version("2025-07-09T05:43:50+0000");
  script_tag(name:"last_modification", value:"2025-07-09 05:43:50 +0000 (Wed, 09 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-07 13:14:16 +0000 (Mon, 07 Jul 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Library (.so) File Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Library (.so) files.");

  script_tag(name:"vuldetect", value:"Note: No report will be created, this routine is only a
  'supportive' detection which can be used by a product specific detection.");

  # nb: Closest fitting tag for such .so files
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");

if( ! soc = ssh_login_or_reuse_connection() )
  exit( 0 );

port = kb_ssh_transport();

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
# /usr/lib64/libldap_r-2.4.so.2.10.12
# /usr/lib64/libnl-xfrm-3.so.200.26.0
# /usr/lib64/liblavfile-2.0.so.0.0.0
#
# nb: We need to make sure to exclude something like e.g. this:
#
# /usr/share/man/man8/libnss_resolve.so.2.8.gz
# /etc/ld.so.conf
# /usr/lib64/.libssl.so.1.1.1f.hmac
# /usr/lib/systemd/user/p11-kit-server.socket
# /etc/ld.so.conf.d
#
# As we will never be able to handle all cases with a regex some known file extensions are excluded
# below. An alternative would be to call "file" on it like described below but that is slow...
#
pattern = "/.+\.so(\.[0-9.a-z]+)?$";

full_path_list = ssh_find_file( file_name:pattern, sock:soc, useregex:TRUE, follow_symlinks:FALSE );
if( ! full_path_list ) {
  ssh_close_connection();
  exit( 0 );
}

found = FALSE;

foreach full_path( full_path_list ) {

  if( ! full_path = chomp( full_path ) )
    continue;

  # nb:
  # - Just a second verification in case we got some unexpected response here
  # - Calling "file --brief" on the file and checking for "shared object" in the response was also
  #   considered but this was quite slow as it would need to have checked all files
  if( ! egrep( string:full_path, pattern:pattern, icase:FALSE ) )
    continue;

  # nb: See comment above
  if( full_path =~ "\.(gz|hmac|conf|cache|conf\.d)$" )
    continue;

  found = TRUE;
  set_kb_item( name:"linux_unix/library_file/ssh-login/" + port + "/files", value:full_path );
}

# nb: We only need to set the generic KB keys once so this was placed outside of the loop above.
if( found ) {
  set_kb_item( name:"linux_unix/library_file/detected", value:TRUE );
  set_kb_item( name:"linux_unix/library_file/ssh-login/detected", value:TRUE );
  set_kb_item( name:"linux_unix/library_file/ssh-login/" + port + "/detected", value:TRUE );
}

ssh_close_connection();

exit( 0 );
