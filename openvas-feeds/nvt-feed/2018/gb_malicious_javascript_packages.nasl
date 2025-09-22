# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113208");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-06-12 13:13:13 +0200 (Tue, 12 Jun 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:24:00 +0000 (Wed, 09 Oct 2019)");
  script_cve_id("CVE-2017-16044", "CVE-2017-16045", "CVE-2017-16046", "CVE-2017-16047", "CVE-2017-16048",
                "CVE-2017-16049", "CVE-2017-16050", "CVE-2017-16051", "CVE-2017-16052", "CVE-2017-16053",
                "CVE-2017-16054", "CVE-2017-16055", "CVE-2017-16056", "CVE-2017-16057", "CVE-2017-16058",
                "CVE-2017-16059", "CVE-2017-16060", "CVE-2017-16061", "CVE-2017-16062", "CVE-2017-16063",
                "CVE-2017-16064", "CVE-2017-16065", "CVE-2017-16066", "CVE-2017-16067", "CVE-2017-16068",
                "CVE-2017-16069", "CVE-2017-16070", "CVE-2017-16071", "CVE-2017-16072", "CVE-2017-16073",
                "CVE-2017-16074", "CVE-2017-16075", "CVE-2017-16076", "CVE-2017-16077", "CVE-2017-16078",
                "CVE-2017-16079", "CVE-2017-16080", "CVE-2017-16081", "CVE-2017-16128", "CVE-2017-16202",
                "CVE-2017-16203", "CVE-2017-16204", "CVE-2017-16205", "CVE-2017-16206", "CVE-2017-16207");
  script_name("Malicious JavaScript Package Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Malware");
  script_dependencies("gb_javascript_packages_ssh_login_detect.nasl");
  script_mandatory_keys("javascript_packages/detected");

  script_tag(name:"summary", value:"Detection and reporting of known malicious JavaScript packages
  or package versions.");

  script_tag(name:"vuldetect", value:"Checks if a malicious JavaScript package or package version is
  present on the target host based on previously collected info.");

  script_tag(name:"impact", value:"The packages mostly extract information from environment
  variables, while some create a remote shell or a command-and-control infrastructure, completely
  comprising the target host.");

  script_tag(name:"affected", value:"The following packages are affected:

  - npm-script-demo

  - pandora-doomsday

  - botbait

  - d3.js

  - jquery.js

  - mariadb

  - mysqljs

  - node-sqlite

  - nodesqlite

  - sqlite.js

  - sqliter

  - node-fabric

  - fabric-js

  - nodefabric

  - sqlserver

  - mssql.js

  - nodemssql

  - gruntcli

  - mssql-node

  - babelcli

  - tkinter

  - node-tkinter

  - node-opensl

  - node-openssl

  - openssl.js

  - opencv.js

  - node-opencv

  - ffmepg

  - nodeffmpeg

  - nodecaffe

  - nodemailer-js

  - nodemailer.js

  - noderequest

  - crossenv

  - http-proxy.js

  - proxy.js

  - mongose

  - shadowsock

  - smb

  - nodesass

  - cross-env.js

  - cofee-script, cofeescript, coffescript, coffe-script

  - jquey

  - discordi.js

  - hooka-tools

  - getcookies

  - nothing-js

  - ladder-text-js

  - boogeyman

  - flatmap-stream included in event-stream version 3.3.6

  - jdb.js

  - db-json.js

  - an0n-chat-lib

  - angluar-cli

  - discord-fix

  - epress

  - commmander, commqnder, commander-js

  - blubird

  - eslint-config-airbnb-standard version 2.0.0, published with a bundled version of eslint-scope that was found to contain malicious code

  - eslint-config-eslint version 5.0.2

  - eslint-scope version 3.7.2

  - rc versions 1.2.9, 1.3.9 and 2.3.9

  - coa versions 2.0.3, 2.0.4, 2.1.1, 2.1.3, 3.0.1 and 3.1.3

  - ua-parser-js versions 0.7.29, 0.8.0 and 1.0.0

  - malicious-npm-package

  - sonatype

  - load-from-cwd-or-npm version 3.0.2

  - smartsearchwp

  - portionfatty12

  - rrgod

  - soket.io, soket.js, foever

  - npm-script-demo

  - regenraotr, regenrator

  - axois");

  script_tag(name:"solution", value:"- Delete the package

  - Clear your npm cache

  - Ensure it is not present in any other package.json files on your system

  - Regenerate your registry credentials, tokens, and any other sensitive credentials that may have
  been present in your environment variables.");

  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/480");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/481");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/482");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/483");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/484");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/485");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/486");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/487");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/488");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/489");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/490");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/491");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/492");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/493");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/494");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/495");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/496");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/497");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/498");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/499");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/500");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/501");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/502");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/503");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/504");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/506");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/507");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/508");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/509");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/510");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/511");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/512");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/513");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/514");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/515");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/516");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/517");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/518");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/519");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/520");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/540");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/541");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/542");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/543");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/544");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/545");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/549");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/649");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/650");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/651");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/677");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/737");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/1584");
  script_xref(name:"URL", value:"https://www.npmjs.com/advisories/1585");
  script_xref(name:"URL", value:"https://blog.sonatype.com/bladabindi-njrat-rat-in-jdb.js-npm-malware");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-7xcv-wvr7-4h6p");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-qv2g-99x4-45x6");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-8mm3-2mcj-cx6r");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-vf8q-pw7h-r2x2");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-mh6f-8j2x-4483");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-q42c-rrp3-r3xm");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-rvww-x6m4-4vc2");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-4xgp-xrg3-c73w");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-m852-866j-69j8");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-pv55-r6j3-wp94");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-hxxf-q3w9-4xgw");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-g2q5-5433-rhrf");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-73qr-pfmq-6rp8");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-pjwm-rvh2-c87w");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-49c6-3wr4-8jr4");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-w8fh-pvq2-x8c4");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-jxf5-7x3j-8j9m");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-fgp6-8g62-qx6w");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-p8fm-w787-x6x3");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-277p-xwpp-3jf7");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-wp2p-q35g-3rjj");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-x6gq-467r-hwcc");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-j3qq-qvc8-c6g7");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-2hqf-qqmq-pgpp");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-322m-p39j-r5m2");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-5x7p-gm79-383m");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-m5p4-7wf9-6w99");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-wpfc-3w63-g4hm");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("misc_func.inc");
include("list_array_func.inc");

# nb: If we ever have packages containing a "@" in the package name we need to change the "@" below
# to something like e.g. "#---#" to handle / support these.
malicious_packages = make_list( "d3.js", "jquery.js", "mariadb", "mysqljs", "node-sqlite",
                                "nodesqlite", "sqlite.js", "sqliter", "node-fabric", "fabric-js",
                                "nodefabric", "sqlserver", "mssql.js", "nodemssql", "gruntcli",
                                "mssql-node", "babelcli", "tkinter", "node-tkinter", "node-opensl",
                                "node-openssl", "openssl.js", "opencv.js", "node-opencv", "ffmpeg",
                                "nodeffmpeg", "nodecaffe", "nodemailer-js", "nodemailer.js", "noderequest",
                                "crossenv", "http-proxy.js", "proxy.js", "mongose", "shadowsock",
                                "smb", "nodesass", "cross-env.js", "cofee-script", "cofeescript",
                                "coffescript", "coffe-script", "jquey", "discordi.js", "npm-script-demo",
                                "pandora-doomsday", "botbait", "hooka-tools", "getcookies", "nothing-js",
                                "ladder-text-js", "boogeyman", "flatmap-stream", "jdb.js", "db-json.js",
                                "an0n-chat-lib", "discord-fix", "angluar-cli", " epress", "event-stream@3.3.6",
                                "commmander", "blubird", "commqnder", "commander-js", "eslint-config-airbnb-standard@2.0.0",
                                "eslint-config-eslint@5.0.2", "eslint-scope@3.7.2", "rc@1.2.9", "rc@1.3.9", "rc@2.3.9",
                                "coa@2.0.3", "coa@2.0.4", "coa@2.1.1", "coa@2.1.3", "coa@3.0.1", "coa@3.1.3",
                                "ua-parser-js@0.7.29", "ua-parser-js@0.8.0", "ua-parser-js@1.0.0", "malicious-npm-package",
                                "sonatype", "load-from-cwd-or-npm@3.0.2", "smartsearchwp", "portionfatty12", "rrgod",
                                "soket.io", "soket.js", "foever", "npm-script-demo", "regenraotr", "regenrator", "axois" );

found = FALSE;
info = make_array();

foreach pkg( malicious_packages ) {

  if( "@" >< pkg ) {
    pkg_split = split( pkg, sep:"@", keep:FALSE );
    pkg = pkg_split[0];
    test_version = pkg_split[1];
  } else {
    test_version = "";
  }

  if( ! get_kb_item( "javascript_package/" + pkg + "/ssh-login/detected" ) )
    continue;

  locations = get_kb_list( "javascript_package/" + pkg + "/ssh-login/location" );
  foreach location( locations ) {

    if( test_version ) {
      version = get_kb_item( "javascript_package/" + pkg + "/" + location + "/ssh-login/version" );
      if( version == test_version ) {
        found = TRUE;
        info[location] = pkg + "@" + version;
      }
    } else {
      found = TRUE;
      info[location] = pkg;
    }
  }
}

if( found ) {
  report = 'The following malicious JavaScript packages were found on the target host:\n\n';
  report += text_format_table( array:info, sep:" | ", columnheader:make_list( "Location", "Package(@version)" ) );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
