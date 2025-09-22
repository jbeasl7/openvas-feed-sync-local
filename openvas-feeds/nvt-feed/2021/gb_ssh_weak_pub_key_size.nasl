# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150712");
  script_version("2024-11-29T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-29 05:05:36 +0000 (Fri, 29 Nov 2024)");
  script_tag(name:"creation_date", value:"2021-09-13 09:44:40 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2021-11-23 10:58:59 +0000 (Tue, 23 Nov 2021)");

  script_name("Weak (Small) Public Key Size(s) (SSH)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_tag(name:"solution_type", value:"Mitigation");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_dependencies("ssh_proto_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("SSH/fingerprints/available");

  script_tag(name:"summary", value:"The remote SSH server uses a weak (too small) public key
  size.");

  script_tag(name:"vuldetect", value:"Checks the public key size of the remote SSH server.

  Currently weak (too small) key sizes are defined as the following:

  - <= 1024 bit for RSA based keys");

  script_tag(name:"insight", value:"- <= 1024 bit for RSA based keys:

  Best practices require that RSA digital signatures be 2048 or more bits long to provide adequate
  security. Key lengths of 1024 are considered deprecated since 2011.");

  script_tag(name:"impact", value:"A man-in-the-middle attacker can exploit this vulnerability to
  record the communication to decrypt the session key and even the messages.");

  script_tag(name:"solution", value:"- <= 1024 bit for RSA based keys:

  Install a RSA public key length of 2048 bits or greater, or to switch to more secure key types.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20220524214031/https://www.linuxminion.com/ssh-server-public-key-too-small/");
  script_xref(name:"URL", value:"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf");
  script_xref(name:"URL", value:"https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

if( ! key = get_kb_item( "SSH/" + port + "/publickey/ssh-rsa" ) )
  exit( 0 );

# Props to https://security.stackexchange.com/questions/42268/how-do-i-get-the-rsa-bit-length-with-the-pubkey-and-openssl
rsa_key = base64_decode( str:key );
hex_rsa_key = hexstr( rsa_key );

counter = 0;

# First 4 bytes: length of next bytes describing the key type
# RSA: 00000007 (hex) -> 7 bytes
for( x = 0; x < 8; x++ ) {
  hex_length_of_key_type += hex_rsa_key[counter];
  counter++;
}
length_of_key_type = hex2dec( xvalue:hex_length_of_key_type );

# Name of keytype
# RSA: 7373682d727361 (hex) -> ssh-rsa
for( x = 0; x < int( length_of_key_type ) * 2; x++ ) {
  hex_type_of_key += hex_rsa_key[counter];
  counter++;
}
type_of_key = hex2str( hex_type_of_key );

# Length of public exponent
# RSA: 00000003 (hex) -> 3 bytes
for( x = 0; x < 8; x++ ) {
  hex_length_of_public_exponent += hex_rsa_key[counter];
  counter++;
}
length_of_public_exponent = hex2dec( xvalue:hex_length_of_public_exponent );

# Public exponent
# RSA: 010001 (hex) -> 65537
for( x = 0; x < int( length_of_public_exponent ) * 2; x++ ) {
  hex_public_exponent += hex_rsa_key[counter];
  counter++;
}
public_exponent = hex2dec( xvalue:hex_public_exponent );

# modulus length, aka bitsize of the key
# RSA: 00000101 -> 257
# First byte is "00" (that first byte was added so that the value is considered positive, because
# the internal encoding rules call for signed integers, the first bit defining the sign).
# -> 256bytes == 2048bits
for( x = 0; x < 8; x++ ) {
  hex_modulus_bytes += hex_rsa_key[counter];
  counter++;
}
modulus_bytes = hex2dec( xvalue:hex_modulus_bytes );
modulus_bits = ( hex2dec( xvalue:hex_modulus_bytes ) -1 ) * 8;

if( int( modulus_bits ) <= 1024 ) {
  security_message( port:port, data:"The remote SSH server uses a public RSA key with the following weak (too small) size: " + modulus_bits );
  exit( 0 );
}

exit( 99 );
