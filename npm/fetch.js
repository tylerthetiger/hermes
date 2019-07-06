#!/usr/bin/env node
// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the LICENSE
// file in the root directory of this source tree.
//

const crypto = require('crypto');
const events = require('events');
const fs = require('fs');
const request = require('request');
const stream = require('stream');
const tar = require('tar');
const util = require('util');
const commandLineArgs = require('command-line-args');

const npmjson = require('./package.json');
const releaseVersion = npmjson.version;

const optionDefinitions = [
  { name: 'dev', type: Boolean }
];
const options = commandLineArgs(optionDefinitions);

// This is a limited replacement for util.promisify(stream.pipeline),
// because node 8 doesn't have stream.pipeline.
function pipeline(readable, writable) {
  return new Promise((resolve, reject) => {
    writable
      .on('finish', resolve)
      .on('error', reject);
    readable
      .on('error', reject)
      .pipe(writable);
  });
}

// This is a limited replacement for events.once, because node 8
// doesn't have it.

function eventsOnce(stream, ev) {
  return new Promise((resolve, reject) => {
    stream.once(ev, resolve);
  });
}

async function readAll(readable) {
  var ret = undefined;
  readable.on('data', (d) => ret = (ret || "") + d.toString());
  await eventsOnce(readable, 'end');
  return ret;
};

async function verifyDigest(file, options = {}) {
  const hasher = crypto.createHash('sha256');
  hasher.setEncoding('hex');

  // This has to be before the pipeline to avoid dropping data
  const hashDigest = readAll(hasher);

  try {
    await pipeline(
      fs.createReadStream(file.name),
      hasher);
  } catch (err) {
    if (err.code !== "ENOENT" || options.hardError) {
      throw err;
    }
    return false;
  }

  if (await hashDigest !== file.digest) {
    if (options.hardError) {
      throw file.name + " digest does not match";
    }
    return false;
  }

  return true;
};

async function verifyAll(files, options = {}) {
  return ((await Promise.all(files.map(file => verifyDigest(file, options))))
          .reduce((acc, cur) => acc && cur));
}

async function downloadRelease(url, dest) {
  console.log("downloading " + dest)
  // pause on response is needed or else data is dropped while
  // creating the events.once Promise after.  Creating the pipeline
  // automatically unpauses.
  const req = request
      .get({
        url,
        headers: {
          "Accept": "application/octet-stream",
          "User-Agent": "fetch like curl",
        }})
      .on('response', response => response.pause())

  const response = await eventsOnce(req, 'response');
  if (response.statusCode === 200) {
    // I could pipe directly to tar.extract here, but I'd rather
    // verify the hash before unpacking.
    await pipeline(response, fs.createWriteStream(dest));
  } else {
    console.error('Response status was ' + response.statusCode);
    // because process.stderr never emits finish or close, awaiting on
    // this pipeline does not work correctly.  Instead, we do the best
    // we can and await on the input ending.
    pipeline(response, process.stderr);
    await eventsOnce(response, 'end');
    throw "fetch failed";
  }
};

async function fetchUnpackVerify(tarball, files, url, destdir) {
  // In dev mode, it's up to the developer to copy the necessary
  // tarballs in place, and no hashes are checked.  This makes
  // iteration faster.

  // If the necessary files exist (hashes are not checked in dev mode), stop.
  if (options.dev) {
    try {
      await Promise.all(files.map(_ => util.promisify(fs.access)(_.name)));
      console.log(files.map(_ => _.name).join(", ") + " existing");
      return;
    } catch (err) {
      if (err.code !== "ENOENT") {
        throw err;
      }
      // fall through
    }
  } else {
    // If we have the necessary files, stop.
    if (await verifyAll(files)) {
      console.log(files.map(_ => _.name).join(", ") + " existing and verified");
      return;
    }

    // If we don't have the tarball, download it.
    if (await verifyDigest(tarball)) {
      console.log(tarball.name + " existing and verified");
    } else {
      await downloadRelease(url, tarball.name);
      await verifyDigest(tarball, { hardError: true });
      console.log(tarball.name + " fetched and verified");
    }
  }

  try {
    await util.promisify(fs.mkdir)(destdir, {recursive:true});
  } catch (err) {
    // node 8 doesn't have the recursive option, so ignore EEXIST
    if (err.code !== "EEXIST") {
      throw err;
    }
  }

  try {
    // Unpack the tarball
    const outputs = [];
    await tar.extract({
      file: tarball.name,
      cwd: destdir,
      onentry: entry => {
        console.log("unpacking " + entry.path);
        outputs.push(entry.path);
      }});
  } catch (err) {
    if (options.dev) {
      // In dev mode, it's likely cli tarballs for other platforms will
      // be missing.  Just log it and move on.
      console.warn("Ignoring missing tarball in dev mode", err);
      return;
    } else {
      throw err;
    }
  }

  if (!options.dev) {
    // Verify the tarball contents
    await verifyAll(files, { hardError: true });

    console.log(tarball.name + " unpacked and verified");
  } else {
    console.log(tarball.name + " unpacked for dev build");
  }
};

async function fuvCliDarwin() {
  // When a new release is created, the url and hashes of all the
  // artifacts will need to be updated here before the npm is built.
  // If not, the build will fail.  TODO We could move the shasums to
  // an external file which would make it easier to cut new releases.

  // To get this URL, do
  // curl -H 'Accept: application/json' https://api.github.com/repos/facebook/hermes/releases/tags/<releaseVersion>
  // and use the 'url' property of the asset with the desired name.
  const url = "https://api.github.com/repos/facebook/hermes/releases/assets/13438908"
  const tarball = {
    name: "hermes-cli-darwin-v" + releaseVersion + ".tar.gz",
    digest: "d9e1cb46a748b5dd1cadd2dd3a55476b017f83e289bec16c94a4f2fb71e214f3"
  };
  const files = [
    {
      name: "osx-bin/hermes",
      digest: "3d166fa2bd0c1177a1a99191c3068e80b05c53242859354c8ce582a73670f899"
    },
    {
      name: "osx-bin/hermes-repl",
      digest: "b11b6e971fd552e222951afc4d6b246ba68d7cf0a20a99cadfd5ca163d3a885d"
    }
  ];
  const destdir = "osx-bin";

  await fetchUnpackVerify(tarball, files, url, destdir);
}

async function fuvCliLinux64() {
  const url = "https://api.github.com/repos/facebook/hermes/releases/assets/13438909"
  const tarball = {
    name: "hermes-cli-linux-v" + releaseVersion + ".tar.gz",
    digest: "37018cda87b6e7905dc4d469f4f26adccc8c99d5795a5161c50d57faf8853e71"
  };
  const destdir = "linux64-bin";
  const files = [
    {
      name: destdir + "/hermes",
      digest: "242ff3dc6ef3c76907028caf110ea17728c46cc00a6cbff8fe28f0d540e88f2e"
    },
    {
      name: destdir + "/hermes-repl",
      digest: "d4f1565b9663f9ce93bef60926d37a41a000f64fa2f3ff145ad613c360a934bb"
    }
  ];

  await fetchUnpackVerify(tarball, files, url, destdir);
}

async function fuvCliWindows64() {
  const url = "https://api.github.com/repos/facebook/hermes/releases/assets/13438910"
  const tarball = {
    name: "hermes-cli-windows-v" + releaseVersion + ".tar.gz",
    digest: "e9d135dcea73726d136a46223a16a468f1c84626776cf27aa1cf441b9c2eec11"
  };
  const destdir = "win64-bin";
  const files = [
    {
      name: destdir + "/hermes.exe",
      digest: "dd0b7f0128cd10ec8a90bd20697e851297bb7b01009f44bfebd667091eb899d8"
    },
    {
      name: destdir + "/hermes-repl.exe",
      digest: "386b1d57a5f1c327ed7dbf05ad1431371d7349a6bcac4f4b7fa3d5ddb9badfc4"
    }
  ];

  await fetchUnpackVerify(tarball, files, url, destdir);
}

async function fuvRuntimeAndroid() {
  const url = "https://api.github.com/repos/facebook/hermes/releases/assets/13438911";
  const tarball = {
    name: "hermes-runtime-android-v" + releaseVersion + ".tar.gz",
    digest: "b9bcab0e70329334d4cb9d137c398b56a22944f727944f11cd11216edb741dff"
  };
  const files = [
    {
      name: "android/hermes-debug.aar",
      digest: "72f8d31074b4245e94632b6387a45cf31e6bf126f5305766eb15115ee16e4fa1"
    },
    {
      name: "android/hermes-release.aar",
      digest: "3e66c31ded795a4e512f8082e56b8cbaa1a6f069cfc1f2c2df9be9ea045183c3"
    }
  ];
  const destdir = "android";

  await fetchUnpackVerify(tarball, files, url, destdir);
}

async function fuvAll() {
  await fuvCliDarwin();
  await fuvCliLinux64();
  await fuvCliWindows64();
  await fuvRuntimeAndroid();
}

fuvAll()
  .catch(err => {
    console.error(err);
    process.exitCode = 1;
  });
