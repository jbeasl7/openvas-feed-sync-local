# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891421");
  script_cve_id("CVE-2015-9096", "CVE-2016-2339", "CVE-2016-7798", "CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901", "CVE-2017-0902", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14033", "CVE-2017-14064", "CVE-2017-17405", "CVE-2017-17742", "CVE-2017-17790", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");
  script_tag(name:"creation_date", value:"2018-07-15 22:00:00 +0000 (Sun, 15 Jul 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-05 21:30:37 +0000 (Thu, 05 Apr 2018)");

  script_name("Debian: Security Advisory (DLA-1421-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1421-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1421-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby2.1' package(s) announced via the DLA-1421-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in the interpreter for the Ruby language. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2015-9096

SMTP command injection in Net::SMTP via CRLF sequences in a RCPT TO or MAIL FROM command.

CVE-2016-2339

Exploitable heap overflow in Fiddle::Function.new.

CVE-2016-7798

Incorrect handling of initialization vector in the GCM mode in the OpenSSL extension.

CVE-2017-0898

Buffer underrun vulnerability in Kernel.sprintf.

CVE-2017-0899

ANSI escape sequence vulnerability in RubyGems.

CVE-2017-0900

DoS vulnerability in the RubyGems query command.

CVE-2017-0901

gem installer allowed a malicious gem to overwrite arbitrary files.

CVE-2017-0902

RubyGems DNS request hijacking vulnerability.

CVE-2017-0903

Max Justicz reported that RubyGems is prone to an unsafe object deserialization vulnerability. When parsed by an application which processes gems, a specially crafted YAML formatted gem specification can lead to remote code execution.

CVE-2017-10784

Yusuke Endoh discovered an escape sequence injection vulnerability in the Basic authentication of WEBrick. An attacker can take advantage of this flaw to inject malicious escape sequences to the WEBrick log and potentially execute control characters on the victim's terminal emulator when reading logs.

CVE-2017-14033

asac reported a buffer underrun vulnerability in the OpenSSL extension. A remote attacker could take advantage of this flaw to cause the Ruby interpreter to crash leading to a denial of service.

CVE-2017-14064

Heap memory disclosure in the JSON library.

CVE-2017-17405

A command injection vulnerability in Net::FTP might allow a malicious FTP server to execute arbitrary commands.

CVE-2017-17742

Aaron Patterson reported that WEBrick bundled with Ruby was vulnerable to an HTTP response splitting vulnerability. It was possible for an attacker to inject fake HTTP responses if a script accepted an external input and output it without modifications.

CVE-2017-17790

A command injection vulnerability in lib/resolv.rb's lazy_initialze might allow a command injection attack. However untrusted input to this function is rather unlikely.

CVE-2018-6914

ooooooo_q discovered a directory traversal vulnerability in the Dir.mktmpdir method in the tmpdir library. It made it possible for attackers to create arbitrary directories or files via a .. (dot dot) in the prefix argument.

CVE-2018-8777

Eric Wong reported an out-of-memory DoS vulnerability related to a large request in WEBrick bundled with Ruby.

CVE-2018-8778

aerodudrizzt found a buffer under-read vulnerability in the Ruby String#unpack method. If a big number was passed with the specifier @, the number was treated as a negative value, and an out-of-buffer read occurred. Attackers could read data on heaps if an script accepts an external input as the argument of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ruby2.1' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.1", ver:"2.1.5-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.1", ver:"2.1.5-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.1-dev", ver:"2.1.5-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.1-doc", ver:"2.1.5-2+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.1-tcltk", ver:"2.1.5-2+deb8u4", rls:"DEB8"))) {
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
