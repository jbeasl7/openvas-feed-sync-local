# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68689");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-7243", "CVE-2010-2950", "CVE-2010-3436", "CVE-2010-3709", "CVE-2010-4150");
  script_name("FreeBSD Ports: php5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following packages are affected:

  php5
   php52

CVE-2010-2950
Format string vulnerability in stream.c in the phar extension in PHP
5.3.x through 5.3.3 allows context-dependent attackers to obtain
sensitive information (memory contents) and possibly execute arbitrary
code via a crafted phar:// URI that is not properly handled by the
phar_stream_flush function, leading to errors in the
php_stream_wrapper_log_error function.  NOTE: this vulnerability exists
because of an incomplete fix for CVE-2010-2094.

CVE-2010-3436
fopen_wrappers.c in PHP 5.3.x through 5.3.3 might allow remote
attackers to bypass open_basedir restrictions via vectors related to
the length of a filename.

CVE-2010-3709
The ZipArchive::getArchiveComment function in PHP 5.2.x through 5.2.14
and 5.3.x through 5.3.3 allows context-dependent attackers to cause a
denial of service (NULL pointer dereference and application crash) via
a crafted ZIP archive.

CVE-2010-4150
Double free vulnerability in the imap_do_open function in the IMAP
extension (ext/imap/php_imap.c) in PHP 5.2 before 5.2.15 and 5.3
before 5.3.4 allows attackers to cause a denial of service (memory
corruption) or possibly execute arbitrary code via unspecified
vectors.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
