# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105218");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-04-24 11:52:03 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Erlang/OTP (Erlang OTP) Detection (SSH Banner)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/erlang/otp/detected");

  script_xref(name:"URL", value:"https://www.erlang.org/");

  script_tag(name:"summary", value:"SSH banner-based detection of Erlang/OTP (Erlang OTP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

# nb:
# - We can "map" / fingerprint the SSH version to a specific OTP version based on the info given
#   here:
#   - https://github.com/erlang/otp/releases (for newer releases)
#   - https://erlang.org/download/ (for some releases the `.README` needs to be consulted)
#   - https://erlangforums.com/tag/erlang-release (At least newer versions are also cross-posted
#     there)
# - Some of the releases doesn't mention the relevant SSH version
# - `ssh-4.0` is included in them from time to time, this is not the real SSH server version and
#   needs to be skipped / ignored
# - This is currently only done for all versions on the GitHub release page which had such a version
#   included.
#   - But this could be extended in the future if required and more info is found
#   - e.g. 28.0.4 on https://github.com/erlang/otp/releases/tag/OTP-28.0.4 didn't included the
#     version info from the ssh package so might be possible that 28.0.3 and 28.0.4 are sharing the
#     same version / banner.
ssh_otp_vers_mapping = make_array(
  "5.3.3", "28.0.3",
  "5.2.11.3", "27.3.4.3",
  "5.1.4.12", "26.2.5.15",
  "5.3.2", "28.0.2",
  "5.2.11.2", "27.3.4.2",
  "5.1.4.11", "26.2.5.14",
  "5.3.1", "28.0.1",
  "5.2.11.1", "27.3.4.1",
  "5.1.4.10", "26.2.5.13",
  "5.2.11", "27.3.4",
  "5.1.4.9", "26.2.5.12",
  "4.15.3.13", "25.3.2.21",
  "5.2.10", "27.3.3",
  "5.1.4.8", "26.2.5.11",
  "4.15.3.12", "25.3.2.20",
  "5.2.9", "27.3.1",
  "5.1.4.7", "26.2.5.10",
  "4.15.3.11", "25.3.2.19",
  "5.2.8", "27.3",
  "5.2.7", "27.2.4",
  "5.1.4.6", "26.2.5.9",
  "4.15.3.10", "25.3.2.18",
  "4.15.3.9", "25.3.2.17",
  "5.1.4.5", "26.2.5.7",
  "5.2.6", "27.2.1",
  "5.2.4", "27.1.3",
  "4.15.3.8", "25.3.2.16",
  "5.1.4.4", "26.2.5.5",
  "5.2.3", "27.1.2",
  "4.15.3.7", "25.3.2.15",
  "5.1.4.3", "26.2.5.4",
  "4.15.3.6", "25.3.2.14",
  "5.2.2", "27.1",
  "5.1.4.2", "26.2.5.3",
  "5.2.1", "27.0.1",
  "4.15.3.5", "25.3.2.13",
  "5.1.4.1", "26.2.5.1",
  "5.1.4", "26.2.4",
  "4.15.3.4", "25.3.2.11",
  "4.13.2.6", "24.3.4.17",
  "4.9.1.5", "22.3.4.27",
  "4.11.1.7", "23.3.4.20",
  "4.15.3.3", "25.3.2.10",
  "5.1.3", "26.2.3",
  "4.13.2.5", "24.3.4.16",
  "5.1.2", "26.2.2",
  "4.15.3.2", "25.3.2.9",
  "5.1.1", "26.2.1",
  "4.15.3.1", "25.3.2.8",
  "4.13.2.4", "24.3.4.15",
  "5.1", "26.2",
  "4.13.2.2", "24.3.4.9",
  "4.15.2", "25.2.3",
  "4.15.1", "25.2",
  "4.11.1.6", "23.3.4.15",
  "4.14.1", "25.0.1",
  "4.13.2.1", "24.3.4.1",
  "4.13.1", "24.2.2",
  "4.11.1.5", "23.3.4.11",
  "4.12.5", "24.1.7",
  "4.11.1.4", "23.3.4.8",
  "4.9.1.4", "22.3.4.22",
  "4.12.3", "24.0.3",
  "4.10.4.1", "23.1.4.1",
  "4.12.2", "24.0.2",
  "4.11.1.2", "23.3.4.2",
  "4.12.1", "24.0.1",
  "4.11.1.1", "23.3.4.1",
  "4.9.1.3", "22.3.4.17",
  "4.11.1", "23.3.1",
  "4.7.6.6", "21.3.8.22",
  "4.10.8", "23.2.6",
  "4.10.7", "23.2.3",
  "4.10.5", "23.1.5",
  "4.10.4", "23.1.4",
  "4.10.3", "23.1.3",
  "4.10.2", "23.1.1",
  "4.9.1.2", "22.3.4.11",
  "4.7.6.5", "21.3.8.18",
  "4.9.1.1", "22.3.4.9",
  "4.9.1", "22.3.3",
  "4.7.6.4", "21.3.8.15",
  "4.7.6.3", "21.3.8.12",
  "4.8.2", "22.2.2",
  "4.7.6.2", "21.3.8.10",
  "4.7.6.1", "21.3.8.7",
  "4.7.6", "21.3.7",
  "4.7.5", "21.3.4",
  "4.7.3", "21.2.2",
  "4.7.2", "21.2"
);

port = ssh_get_port( default:22 );

if( ! banner = ssh_get_serverbanner( port:port ) )
  exit( 0 );

# SSH-2.0-Erlang/4.10.7
# SSH-2.0-Erlang/5.1.4.7
if( egrep( string:banner, pattern:"SSH-[0-9.]+-Erlang", icase:FALSE ) ) {

  ssh_version = "unknown";
  otp_version = "unknown";
  install = port + "/tcp";

  set_kb_item( name:"erlang/otp/detected", value:TRUE );
  set_kb_item( name:"erlang/otp/ssh/detected", value:TRUE );
  set_kb_item( name:"erlang/otp/ssh/port", value:port );

  ssh_vers = eregmatch( pattern:"SSH-[0-9.]+-Erlang/([0-9.]+)", string:banner, icase:TRUE );
  if( ssh_vers[1] ) {
    ssh_version = ssh_vers[1];

    if( otp_vers = ssh_otp_vers_mapping[ssh_version] ) {
      otp_version = otp_vers;
      extra = "  Note: The OTP version was determined from the SSH version based on the vendor release notes.";
    }
  }

  ssh_cpe = build_cpe( value:ssh_version, exp:"^([0-9.]+)", base:"cpe:/a:erlang:ssh:" );
  if( ! ssh_cpe )
    ssh_cpe = "cpe:/a:erlang:ssh";

  otp_cpe = build_cpe( value:otp_version, exp:"^([0-9.]+)", base:"cpe:/a:erlang:erlang%2fotp:" );
  if( ! otp_cpe )
    otp_cpe = "cpe:/a:erlang:erlang%2fotp";

  register_product( cpe:ssh_cpe, location:install, port:port, service:"ssh" );
  register_product( cpe:otp_cpe, location:install, port:port, service:"ssh" );

  report = build_detection_report( app:"Erlang/OTP (Erlang OTP) SSH",
                                   version:ssh_version,
                                   install:install,
                                   cpe:ssh_cpe );
  report += '\n\n';
  report += build_detection_report( app:"Erlang/OTP (Erlang OTP)",
                                    version:otp_version,
                                    install:install,
                                    extra:extra,
                                    cpe:otp_cpe );
  report += '\n\n';
  report += 'Concluded from product identification result:\n  ' + banner;

  log_message( port:0, data:report );
}

exit( 0 );
