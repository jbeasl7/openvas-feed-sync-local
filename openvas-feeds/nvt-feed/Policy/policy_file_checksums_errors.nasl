# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103943");
  script_version("2023-09-07T05:05:21+0000");
  script_name("File Checksums: Errors");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-09-07 05:05:21 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"creation_date", value:"2013-08-13 13:33:56 +0200 (Tue, 13 Aug 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("Policy/policy_file_checksums.nasl");
  script_mandatory_keys("policy/file_checksums/started");

  script_tag(name:"summary", value:"List files with checksum errors (missing files or other errors).");

  script_tag(name:"qod", value:"98"); # direct authenticated file analysis is pretty reliable

  exit(0);
}

md5errors      = get_kb_list( "policy/file_checksums/md5_error_list" );
sha1errors     = get_kb_list( "policy/file_checksums/sha1_error_list" );
general_errors = get_kb_list( "policy/file_checksums/general_error_list" );
invalid_lines  = get_kb_list( "policy/file_checksums/invalid_list" );

if( md5errors || sha1errors ) {

  # Sort to not report changes on delta reports if just the order is different
  if( md5errors )  md5errors  = sort( md5errors );
  if( sha1errors ) sha1errors = sort( sha1errors );

  report += 'The following files are missing or showed some errors during the check:\n\n';
  report += 'Filename|Result|Errorcode;\n';

  foreach error( md5errors ) {
    report += error + '\n';
  }
  foreach error( sha1errors ) {
    report += error + '\n';
  }
  report += '\n';
}

if( general_errors ) {

  # Sort to not report changes on delta reports if just the order is different
  general_errors = sort( general_errors );

  report += 'The following errors occurred during the check:\n\n';

  foreach error( general_errors ) {
    report += error + '\n';
  }
  report += '\n';
}

if( invalid_lines ) {

  # Sort to not report changes on delta reports if just the order is different
  invalid_lines = sort( invalid_lines );

  report += 'The following invalid lines were identified within the uploaded policy file:\n\n';
  report += 'Line|Result|Errorcode;\n';

  foreach error( invalid_lines ) {
    report += error + '\n';
  }
  report += '\n';
}

if( strlen( report ) > 0 )
  log_message( port:0, data:report );

exit( 0 );
