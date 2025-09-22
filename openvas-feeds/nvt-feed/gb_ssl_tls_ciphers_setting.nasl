# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900238");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2010-04-16 11:02:50 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSL/TLS: Cipher Settings");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("SSL and TLS");

  script_tag(name:"summary", value:"This plugin allows to overwrite the internal classification of
  SSL/TLS Ciphers used for the reporting of Strong, Medium and Weak Ciphers within the following
  VTs:

  - SSL/TLS: Report Non Weak Cipher Suites (OID: 1.3.6.1.4.1.25623.1.0.103441)

  - SSL/TLS: Report Medium Cipher Suites (OID: 1.3.6.1.4.1.25623.1.0.902816)

  - SSL/TLS: Report Weak Cipher Suites (OID: 1.3.6.1.4.1.25623.1.0.103440)

  - SSL/TLS: Report 'Null' Cipher Suites (OID: 1.3.6.1.4.1.25623.1.0.108022)");

  script_tag(name:"qod_type", value:"remote_banner");

# nb: How to add a new cipher preference. (Is same text as below script_add_preference block):
#     Pref value: if cipher as listed in gb_ssl_tls_ciphers.inc has after the ":"
#       "Weak cipher": pref value has to be "Weak cipher;Null cipher;Medium cipher;Strong cipher"
#       "Null cipher": pref value has to be "Null cipher;Weak cipher;Medium cipher;Strong cipher"
#       "Medium cipher": pref value has to be "Medium cipher;Null cipher;Weak cipher;Strong cipher"
#       "Strong cipher": pref value has to be "Strong cipher;Null cipher;Weak cipher;Medium cipher"
#     Pref name: the part before the ":" in the sslv3_tls_ciphers cipher key
#     Pref type: Always "radio"
#     Pref id: Stays the same when name is modified. For new prefs it is the id of current last pref plus one
#     location: New preferences are put at the end of the list of script_add_preference calls
  script_add_preference(name:"TLS_RSA_WITH_RC4_128_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:1);
  script_add_preference(name:"TLS_DH_anon_WITH_RC4_128_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:2);
  script_add_preference(name:"TLS_KRB5_WITH_RC4_128_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:3);
  script_add_preference(name:"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:4);
  script_add_preference(name:"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:5);
  script_add_preference(name:"TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA (Draft2)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:6);
  script_add_preference(name:"TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA (Draft2)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:7);
  script_add_preference(name:"TLS_CHACHA20_POLY1305_SHA256", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:8);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:9);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:10);
  script_add_preference(name:"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:11);
  script_add_preference(name:"TLS_PSK_WITH_CHACHA20_POLY1305_SHA256", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:12);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:13);
  script_add_preference(name:"TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:14);
  script_add_preference(name:"TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:15);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_DES_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:16);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:17);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_DES_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:18);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (Draft) or TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:19);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:20);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:21);
  script_add_preference(name:"TLS_ECDH_anon_WITH_DES_CBC_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:22);
  script_add_preference(name:"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:23);
  script_add_preference(name:"TLS_KRB5_WITH_3DES_EDE_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:24);
  script_add_preference(name:"TLS_KRB5_WITH_3DES_EDE_CBC_MD5 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:25);
  script_add_preference(name:"TLS_KRB5_WITH_DES_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:26);
  script_add_preference(name:"TLS_KRB5_WITH_DES_CBC_MD5 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:27);
  script_add_preference(name:"TLS_AES_256_GCM_SHA384", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:28);
  script_add_preference(name:"TLS_ECCPWD_WITH_AES_128_GCM_SHA256 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:29);
  script_add_preference(name:"TLS_ECCPWD_WITH_AES_128_CCM_SHA256 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:30);
  script_add_preference(name:"TLS_ECCPWD_WITH_AES_256_CCM_SHA384 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:31);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:32);
  script_add_preference(name:"TLS_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:33);
  script_add_preference(name:"TLS_RSA_WITH_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:34);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:35);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:36);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:37);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:38);
  script_add_preference(name:"TLS_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:39);
  script_add_preference(name:"TLS_PSK_WITH_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:40);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:41);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:42);
  script_add_preference(name:"TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:43);
  script_add_preference(name:"TLS_RSA_PSK_WITH_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:44);
  script_add_preference(name:"TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:45);
  script_add_preference(name:"TLS_DHE_PSK_WITH_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:46);
  script_add_preference(name:"TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:47);
  script_add_preference(name:"TLS_DHE_RSA_WITH_SALSA20_SHA1 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:48);
  script_add_preference(name:"TLS_RSA_FIPS_WITH_DES_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:49);
  script_add_preference(name:"TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:50);
  script_add_preference(name:"TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:51);
  script_add_preference(name:"TLS_RSA_FIPS_WITH_DES_CBC_SHA_2 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:52);
  script_add_preference(name:"TLS_RSA_WITH_DES_CBC_MD5 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:53);
  script_add_preference(name:"TLS_RSA_WITH_3DES_EDE_CBC_MD5 (Draft)", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:54);
  script_add_preference(name:"TLS_DH_DSS_WITH_AES_256_CBC_SHA", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:55);
  script_add_preference(name:"TLS_DH_RSA_WITH_AES_256_CBC_SHA", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:56);
  script_add_preference(name:"TLS_DHE_DSS_WITH_AES_256_CBC_SHA", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:57);
  script_add_preference(name:"TLS_DHE_RSA_WITH_AES_256_CBC_SHA", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:58);
  script_add_preference(name:"TLS_DH_anon_WITH_AES_256_CBC_SHA", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:59);
  script_add_preference(name:"TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA (Draft1)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:60);
  script_add_preference(name:"TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA (Draft1)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:61);
  script_add_preference(name:"TLS_RSA_WITH_NULL_SHA256", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:62);
  script_add_preference(name:"TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:63);
  script_add_preference(name:"TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:64);
  script_add_preference(name:"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:65);
  script_add_preference(name:"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:66);
  script_add_preference(name:"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:67);
  script_add_preference(name:"TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:68);
  script_add_preference(name:"TLS_PSK_WITH_NULL_SHA256", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:69);
  script_add_preference(name:"TLS_DHE_PSK_WITH_NULL_SHA256", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:70);
  script_add_preference(name:"TLS_RSA_PSK_WITH_NULL_SHA256", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:71);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_NULL_SHA256", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:72);
  script_add_preference(name:"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:73);
  script_add_preference(name:"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:74);
  script_add_preference(name:"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:75);
  script_add_preference(name:"TLS_GOSTR341094_WITH_28147_CNT_IMIT (Draft)", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:76);
  script_add_preference(name:"TLS_GOSTR341001_WITH_28147_CNT_IMIT (Draft)", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:77);
  script_add_preference(name:"TLS_ECCPWD_WITH_AES_256_GCM_SHA384 (Draft)", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:78);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:79);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:80);
  script_add_preference(name:"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (Draft)", type:"radio", value:"Strong cipher;Null cipher;Weak cipher;Medium cipher", id:81);
  script_add_preference(name:"TLS_RSA_WITH_AES_256_CCM", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:82);
  script_add_preference(name:"TLS_DHE_RSA_WITH_AES_256_CCM", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:83);
  script_add_preference(name:"TLS_PSK_WITH_AES_256_CCM", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:84);
  script_add_preference(name:"TLS_DHE_PSK_WITH_AES_256_CCM", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:85);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_AES_256_CCM", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:86);
  script_add_preference(name:"TLS_KRB5_EXPORT_WITH_RC4_40_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:87);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_RC4_128_SHA (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:88);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (Draft) or TLS_ECDH_ECDSA_EXPORT_WITH_RC4_40_SHA (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:89);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (Draft) or TLS_ECDH_ECDSA_EXPORT_WITH_RC4_56_SHA (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:90);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_RC4_128_SHA (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:91);
  script_add_preference(name:"TLS_ECDH_RSA_EXPORT_WITH_RC4_40_SHA (Draft) or TLS_SRP_SHA_WITH_AES_128_CBC_SHA (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:92);
  script_add_preference(name:"TLS_ECDH_RSA_EXPORT_WITH_RC4_56_SHA (Draft) or TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:93);
  script_add_preference(name:"TLS_ECDH_anon_WITH_RC4_128_SHA (Draft) or TLS_SRP_SHA_WITH_AES_256_CBC_SHA (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:94);
  script_add_preference(name:"TLS_KRB5_WITH_RC4_128_SHA (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:95);
  script_add_preference(name:"TLS_KRB5_WITH_RC4_128_MD5 (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:96);
  script_add_preference(name:"TLS_KRB5_WITH_AES_128_CBC_SHA (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:97);
  script_add_preference(name:"TLS_KRB5_WITH_AES_256_CBC_SHA (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:98);
  script_add_preference(name:"TLS_PSK_WITH_NULL_SHA384", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:99);
  script_add_preference(name:"TLS_DHE_PSK_WITH_NULL_SHA384", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:100);
  script_add_preference(name:"TLS_RSA_PSK_WITH_NULL_SHA384", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:101);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_NULL_SHA384", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:102);
  script_add_preference(name:"TLS_SHA256_SHA256 (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:103);
  script_add_preference(name:"TLS_SHA384_SHA384 (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:104);
  script_add_preference(name:"TLS_RSA_WITH_RC2_CBC_MD5 (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:105);
  script_add_preference(name:"TLS_RSA_WITH_IDEA_CBC_MD5 (Draft)", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:106);
  script_add_preference(name:"TLS_RSA_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:107);
  script_add_preference(name:"TLS_FORTEZZA_KEA_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:108);
  script_add_preference(name:"TLS_PSK_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:109);
  script_add_preference(name:"TLS_DHE_PSK_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:110);
  script_add_preference(name:"TLS_RSA_PSK_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:111);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:112);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:113);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:114);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:115);
  script_add_preference(name:"TLS_ECDH_anon_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:116);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_NULL_SHA", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:117);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_NULL_SHA (Draft)", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:118);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_NULL_SHA (Draft)", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:119);
  script_add_preference(name:"TLS_ECDH_anon_NULL_WITH_SHA (Draft) or TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA (Draft)", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:120);
  script_add_preference(name:"TLS_KRB5_WITH_NULL_SHA (Draft)", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:121);
  script_add_preference(name:"TLS_KRB5_WITH_NULL_MD5 (Draft)", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:122);
  script_add_preference(name:"TLS_GOSTR341094_WITH_NULL_GOSTR3411 (Draft)", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:123);
  script_add_preference(name:"TLS_GOSTR341001_WITH_NULL_GOSTR3411 (Draft)", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:124);
  script_add_preference(name:"TLS_RSA_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:125);
  script_add_preference(name:"TLS_KRB5_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:126);
  script_add_preference(name:"TLS_DHE_DSS_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:127);
  script_add_preference(name:"TLS_PSK_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:128);
  script_add_preference(name:"TLS_DHE_PSK_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:129);
  script_add_preference(name:"TLS_RSA_PSK_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:130);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:131);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:132);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:133);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:134);
  script_add_preference(name:"TLS_ECDH_anon_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:135);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_RC4_128_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:136);
  script_add_preference(name:"TLS_NULL_WITH_NULL_NULL", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:137);
  script_add_preference(name:"TLS_RSA_EXPORT_WITH_RC4_40_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:138);
  script_add_preference(name:"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:139);
  script_add_preference(name:"TLS_KRB5_WITH_DES_CBC_MD5", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:140);
  script_add_preference(name:"TLS_KRB5_WITH_3DES_EDE_CBC_MD5", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:141);
  script_add_preference(name:"TLS_KRB5_WITH_IDEA_CBC_MD5", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:142);
  script_add_preference(name:"TLS_KRB5_EXPORT_WITH_RC4_40_MD5", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:143);
  script_add_preference(name:"TLS_RSA_WITH_AES_128_CCM", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:144);
  script_add_preference(name:"TLS_DHE_RSA_WITH_AES_128_CCM", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:145);
  script_add_preference(name:"TLS_PSK_WITH_AES_128_CCM", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:146);
  script_add_preference(name:"TLS_DHE_PSK_WITH_AES_128_CCM", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:147);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_AES_128_CCM", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:148);
  script_add_preference(name:"TLS_RSA_WITH_NULL_MD5", type:"radio", value:"Null cipher;Weak cipher;Medium cipher;Strong cipher", id:149);
  script_add_preference(name:"TLS_RSA_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:150);
  script_add_preference(name:"TLS_RSA_WITH_AES_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:151);
  script_add_preference(name:"TLS_DH_DSS_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:152);
  script_add_preference(name:"TLS_DH_RSA_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:153);
  script_add_preference(name:"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:154);
  script_add_preference(name:"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:155);
  script_add_preference(name:"TLS_DH_DSS_WITH_AES_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:156);
  script_add_preference(name:"TLS_DH_RSA_WITH_AES_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:157);
  script_add_preference(name:"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:158);
  script_add_preference(name:"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:159);
  script_add_preference(name:"TLS_DH_anon_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:160);
  script_add_preference(name:"TLS_DH_anon_WITH_AES_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:161);
  script_add_preference(name:"TLS_RSA_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:162);
  script_add_preference(name:"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:163);
  script_add_preference(name:"TLS_DH_RSA_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:164);
  script_add_preference(name:"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:165);
  script_add_preference(name:"TLS_DH_DSS_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:166);
  script_add_preference(name:"TLS_DH_anon_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:167);
  script_add_preference(name:"TLS_PSK_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:168);
  script_add_preference(name:"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:169);
  script_add_preference(name:"TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:170);
  script_add_preference(name:"TLS_PSK_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:171);
  script_add_preference(name:"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:172);
  script_add_preference(name:"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:173);
  script_add_preference(name:"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:174);
  script_add_preference(name:"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:175);
  script_add_preference(name:"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:176);
  script_add_preference(name:"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:177);
  script_add_preference(name:"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:178);
  script_add_preference(name:"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:179);
  script_add_preference(name:"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:180);
  script_add_preference(name:"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:181);
  script_add_preference(name:"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:182);
  script_add_preference(name:"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:183);
  script_add_preference(name:"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:184);
  script_add_preference(name:"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:185);
  script_add_preference(name:"TLS_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:186);
  script_add_preference(name:"TLS_AES_128_CCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:187);
  script_add_preference(name:"TLS_AES_128_CCM_8_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:188);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:189);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:190);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:191);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:192);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:193);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:194);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:195);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:196);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:197);
  script_add_preference(name:"TLS_RSA_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:198);
  script_add_preference(name:"TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:199);
  script_add_preference(name:"TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:200);
  script_add_preference(name:"TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:201);
  script_add_preference(name:"TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:202);
  script_add_preference(name:"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:203);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:204);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:205);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:206);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:207);
  script_add_preference(name:"TLS_RSA_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:208);
  script_add_preference(name:"TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:209);
  script_add_preference(name:"TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:210);
  script_add_preference(name:"TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:211);
  script_add_preference(name:"TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:212);
  script_add_preference(name:"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:213);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:214);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:215);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:216);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:217);
  script_add_preference(name:"TLS_PSK_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:218);
  script_add_preference(name:"TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:219);
  script_add_preference(name:"TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:220);
  script_add_preference(name:"TLS_PSK_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:221);
  script_add_preference(name:"TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:222);
  script_add_preference(name:"TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:223);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:224);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:225);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:226);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:227);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:228);
  script_add_preference(name:"TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:229);
  script_add_preference(name:"TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:230);
  script_add_preference(name:"TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:231);
  script_add_preference(name:"TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:232);
  script_add_preference(name:"TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:233);
  script_add_preference(name:"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:234);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:235);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:236);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:237);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:238);
  script_add_preference(name:"TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:239);
  script_add_preference(name:"TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:240);
  script_add_preference(name:"TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:241);
  script_add_preference(name:"TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:242);
  script_add_preference(name:"TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:243);
  script_add_preference(name:"TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:244);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:245);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:246);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:247);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:248);
  script_add_preference(name:"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:249);
  script_add_preference(name:"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:250);
  script_add_preference(name:"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:251);
  script_add_preference(name:"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:252);
  script_add_preference(name:"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:253);
  script_add_preference(name:"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:254);
  script_add_preference(name:"TLS_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:255);
  script_add_preference(name:"TLS_FORTEZZA_KEA_WITH_RC4_128_SHA or TLS_KRB5_WITH_DES_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:256);
  script_add_preference(name:"TLS_RSA_WITH_SEED_CBC_SHA", type:"radio", value:"Weak cipher;Null cipher;Medium cipher;Strong cipher", id:257);
  script_add_preference(name:"TLS_RSA_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:258);
  script_add_preference(name:"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:259);
  script_add_preference(name:"TLS_DH_RSA_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:260);
  script_add_preference(name:"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:261);
  script_add_preference(name:"TLS_DH_DSS_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:262);
  script_add_preference(name:"TLS_DH_anon_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:263);
  script_add_preference(name:"TLS_PSK_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:264);
  script_add_preference(name:"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:265);
  script_add_preference(name:"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:266);
  script_add_preference(name:"TLS_PSK_WITH_AES_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:267);
  script_add_preference(name:"TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:268);
  script_add_preference(name:"TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:269);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:270);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:271);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:272);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:273);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:274);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:275);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:276);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:277);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:278);
  script_add_preference(name:"TLS_RSA_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:279);
  script_add_preference(name:"TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:280);
  script_add_preference(name:"TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:281);
  script_add_preference(name:"TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:282);
  script_add_preference(name:"TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:283);
  script_add_preference(name:"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:284);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:285);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:286);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:287);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:288);
  script_add_preference(name:"TLS_RSA_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:289);
  script_add_preference(name:"TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:290);
  script_add_preference(name:"TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:291);
  script_add_preference(name:"TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:292);
  script_add_preference(name:"TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:293);
  script_add_preference(name:"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:294);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:295);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:296);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:297);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:298);
  script_add_preference(name:"TLS_PSK_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:299);
  script_add_preference(name:"TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:300);
  script_add_preference(name:"TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:301);
  script_add_preference(name:"TLS_PSK_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:302);
  script_add_preference(name:"TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:303);
  script_add_preference(name:"TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:304);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:305);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:306);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:307);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:308);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:309);
  script_add_preference(name:"TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:310);
  script_add_preference(name:"TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:311);
  script_add_preference(name:"TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:312);
  script_add_preference(name:"TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:313);
  script_add_preference(name:"TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:314);
  script_add_preference(name:"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:315);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:316);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:317);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:318);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:319);
  script_add_preference(name:"TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:320);
  script_add_preference(name:"TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:321);
  script_add_preference(name:"TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:322);
  script_add_preference(name:"TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:323);
  script_add_preference(name:"TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:324);
  script_add_preference(name:"TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:325);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:326);
  script_add_preference(name:"TLS_RSA_WITH_AES_128_CCM_8", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:327);
  script_add_preference(name:"TLS_RSA_WITH_AES_256_CCM_8", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:328);
  script_add_preference(name:"TLS_DHE_RSA_WITH_AES_128_CCM_8", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:329);
  script_add_preference(name:"TLS_DHE_RSA_WITH_AES_256_CCM_8", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:330);
  script_add_preference(name:"TLS_PSK_WITH_AES_128_CCM_8", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:331);
  script_add_preference(name:"TLS_PSK_WITH_AES_256_CCM_8", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:332);
  script_add_preference(name:"TLS_PSK_DHE_WITH_AES_128_CCM_8", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:333);
  script_add_preference(name:"TLS_PSK_DHE_WITH_AES_256_CCM_8", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:334);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:335);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:336);
  script_add_preference(name:"TLS_RSA_WITH_IDEA_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:337);
  script_add_preference(name:"TLS_RSA_WITH_DES_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:338);
  script_add_preference(name:"TLS_RSA_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:339);
  script_add_preference(name:"TLS_DH_DSS_WITH_DES_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:340);
  script_add_preference(name:"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:341);
  script_add_preference(name:"TLS_DH_RSA_WITH_DES_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:342);
  script_add_preference(name:"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:343);
  script_add_preference(name:"TLS_DHE_DSS_WITH_DES_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:344);
  script_add_preference(name:"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:345);
  script_add_preference(name:"TLS_DHE_RSA_WITH_DES_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:346);
  script_add_preference(name:"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:347);
  script_add_preference(name:"TLS_DH_anon_WITH_DES_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:348);
  script_add_preference(name:"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:349);
  script_add_preference(name:"TLS_KRB5_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:350);
  script_add_preference(name:"TLS_KRB5_WITH_IDEA_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:351);
  script_add_preference(name:"TLS_RSA_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:352);
  script_add_preference(name:"TLS_DH_DSS_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:353);
  script_add_preference(name:"TLS_DH_RSA_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:354);
  script_add_preference(name:"TLS_DHE_DSS_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:355);
  script_add_preference(name:"TLS_DHE_RSA_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:356);
  script_add_preference(name:"TLS_DH_anon_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:357);
  script_add_preference(name:"TLS_RSA_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:358);
  script_add_preference(name:"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:359);
  script_add_preference(name:"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:360);
  script_add_preference(name:"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:361);
  script_add_preference(name:"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:362);
  script_add_preference(name:"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:363);
  script_add_preference(name:"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:364);
  script_add_preference(name:"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:365);
  script_add_preference(name:"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:366);
  script_add_preference(name:"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:367);
  script_add_preference(name:"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:368);
  script_add_preference(name:"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:369);
  script_add_preference(name:"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:370);
  script_add_preference(name:"TLS_PSK_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:371);
  script_add_preference(name:"TLS_PSK_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:372);
  script_add_preference(name:"TLS_PSK_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:373);
  script_add_preference(name:"TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:374);
  script_add_preference(name:"TLS_DHE_PSK_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:375);
  script_add_preference(name:"TLS_DHE_PSK_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:376);
  script_add_preference(name:"TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:377);
  script_add_preference(name:"TLS_RSA_PSK_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:378);
  script_add_preference(name:"TLS_RSA_PSK_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:379);
  script_add_preference(name:"TLS_DH_DSS_WITH_SEED_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:380);
  script_add_preference(name:"TLS_DH_RSA_WITH_SEED_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:381);
  script_add_preference(name:"TLS_DHE_DSS_WITH_SEED_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:382);
  script_add_preference(name:"TLS_DHE_RSA_WITH_SEED_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:383);
  script_add_preference(name:"TLS_DH_anon_WITH_SEED_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:384);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:385);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:386);
  script_add_preference(name:"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:387);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:388);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:389);
  script_add_preference(name:"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:390);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:391);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:392);
  script_add_preference(name:"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:393);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:394);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:395);
  script_add_preference(name:"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:396);
  script_add_preference(name:"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:397);
  script_add_preference(name:"TLS_ECDH_anon_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:398);
  script_add_preference(name:"TLS_ECDH_anon_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:399);
  script_add_preference(name:"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:400);
  script_add_preference(name:"TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:401);
  script_add_preference(name:"TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:402);
  script_add_preference(name:"TLS_SRP_SHA_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:403);
  script_add_preference(name:"TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:404);
  script_add_preference(name:"TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:405);
  script_add_preference(name:"TLS_SRP_SHA_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:406);
  script_add_preference(name:"TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:407);
  script_add_preference(name:"TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:408);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:409);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:410);
  script_add_preference(name:"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", type:"radio", value:"Medium cipher;Null cipher;Weak cipher;Strong cipher", id:411);

# nb: How to add a new cipher preference. (Is same text as above script_add_preference block):
#     Pref value: if cipher as listed in gb_ssl_tls_ciphers.inc has after the ":"
#       "Weak cipher": pref value has to be "Weak cipher;Null cipher;Medium cipher;Strong cipher"
#       "Null cipher": pref value has to be "Null cipher;Weak cipher;Medium cipher;Strong cipher"
#       "Medium cipher": pref value has to be "Medium cipher;Null cipher;Weak cipher;Strong cipher"
#       "Strong cipher": pref value has to be "Strong cipher;Null cipher;Weak cipher;Medium cipher"
#     Pref name: the part before the ":" in the sslv3_tls_ciphers cipher key
#     Pref type: Always "radio"
#     Pref id: Stays the same when name is modified. For new prefs it is the id of current last pref plus one
#     location: New preferences are put at the end of the list of script_add_preference calls

  exit(0);
}

include("gb_ssl_tls_ciphers.inc");

cipher_arrays = make_list(keys(sslv3_tls_ciphers));

foreach c( keys( cipher_arrays ) ) {

  n = split( cipher_arrays[c], sep:" : ", keep:FALSE );
  if( isnull( n[0] ) || isnull( n[1] ) )
    continue;

  v = script_get_preference( n[0] );
  if( ! v )
    continue;

  if( v >!< n[1] )
    set_kb_item( name:"ssl/ciphers/override/" + n[0] + " : " + n[1], value:v );
}

exit( 0 );
